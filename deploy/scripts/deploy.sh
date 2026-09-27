#!/bin/sh
#
# Custom-API customs gateway: build and deploy driver.
#
# Runs on the development host (or on any machine with the Go toolchain) and
# produces a FreeBSD release, ships it to a target, installs it and runs the
# end-to-end acceptance test.
#
# Usage:
#   ./deploy/scripts/deploy.sh build            cross-compile the FreeBSD release
#   ./deploy/scripts/deploy.sh stage            assemble dist/customapi-<version>/
#   ./deploy/scripts/deploy.sh ship             copy the release to the target
#   ./deploy/scripts/deploy.sh install          run the installer on the target
#   ./deploy/scripts/deploy.sh test             run the acceptance test on the target
#   ./deploy/scripts/deploy.sh all              build + stage + ship + install + test
#   ./deploy/scripts/deploy.sh local-test       run go test ./... on the host
#   ./deploy/scripts/deploy.sh clean            remove build output
#
# Target selection, in order of precedence:
#   --target USER@HOST   explicit
#   $CUSTOMAPI_TARGET    environment
#   customapi-bsd        the SSH alias created for the libvirt test VM
#
# The FreeBSD test VM is managed with libvirt; see docs/VM-zh.md.

set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
SRC="${ROOT}/src/customapi"
DIST="${ROOT}/dist"
VERSION=$(sed -n 's/.*Version *= *"\([^"]*\)".*/\1/p' "${SRC}/internal/version/version.go" 2>/dev/null | head -1)
[ -n "${VERSION}" ] || VERSION=dev
COMMIT=$(git -C "${ROOT}" rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILT=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
STAGE="${DIST}/customapi-${VERSION}"
TARGET=${CUSTOMAPI_TARGET:-customapi-bsd}
REMOTE_DIR=/tmp/customapi-release
GOOS_TARGET=freebsd
GOARCH_TARGET=amd64

# Deliberately quiet: the deploy log should show outcomes, not command echo.
log()  { printf '\033[1m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

require() {
	command -v "$1" >/dev/null 2>&1 || die "$1 is required but not found in PATH"
}

# ---------------------------------------------------------------------------
# build
# ---------------------------------------------------------------------------

do_build() {
	require go
	log "building customs ${VERSION} for ${GOOS_TARGET}/${GOARCH_TARGET}"
	mkdir -p "${DIST}/bin"

	# CGO is disabled so the binaries are static and need no FreeBSD ports:
	# the whole point is a single-file drop-in that runs on a stock system.
	LDFLAGS="-s -w \
		-X github.com/redstone/customapi/internal/version.Version=${VERSION} \
		-X github.com/redstone/customapi/internal/version.Commit=${COMMIT} \
		-X github.com/redstone/customapi/internal/version.BuildTime=${BUILT}"

	for cmd in customsd benchd customsctl; do
		out="${DIST}/bin/${cmd}"
		log "  ${cmd}"
		(cd "${SRC}" && env CGO_ENABLED=0 GOOS="${GOOS_TARGET}" GOARCH="${GOARCH_TARGET}" \
			go build -trimpath -ldflags "${LDFLAGS}" -o "${out}" "./cmd/${cmd}")
	done

	# Also verify the module builds natively, so a developer does not discover
	# a platform-specific problem only at deploy time.
	log "  native build check"
	(cd "${SRC}" && CGO_ENABLED=0 go build ./... >/dev/null)

	log "binaries:"
	ls -l "${DIST}/bin" | tail -n +2 | awk '{printf "  %-12s %8d bytes\n", $9, $5}'
}

# ---------------------------------------------------------------------------
# stage
# ---------------------------------------------------------------------------

do_stage() {
	[ -x "${DIST}/bin/customsd" ] || die "nothing to stage; run 'build' first"
	log "staging ${STAGE}"
	rm -rf "${STAGE}"
	mkdir -p "${STAGE}/bin" "${STAGE}/etc" "${STAGE}/rc.d" "${STAGE}/scripts" "${STAGE}/docs"

	cp "${DIST}/bin/customsd" "${DIST}/bin/benchd" "${DIST}/bin/customsctl" "${STAGE}/bin/"
	cp "${ROOT}/deploy/etc/customs.json"           "${STAGE}/etc/"
	cp "${ROOT}/deploy/etc/customsd.env.example"   "${STAGE}/etc/"
	cp "${ROOT}/deploy/rc.d/customsd"              "${STAGE}/rc.d/"
	cp "${ROOT}/deploy/rc.d/benchd"                "${STAGE}/rc.d/"
	cp "${ROOT}/deploy/scripts/install.sh"         "${STAGE}/scripts/"
	cp "${ROOT}/deploy/scripts/smoke-test.sh"      "${STAGE}/scripts/"
	cp "${ROOT}/deploy/scripts/mock-upstream.py"   "${STAGE}/scripts/"
	cp "${ROOT}/deploy/scripts/customsd-wrapper.sh" "${STAGE}/scripts/"
	cp "${ROOT}/deploy/scripts/intel-test.sh"       "${STAGE}/scripts/"
	cp "${ROOT}/deploy/scripts/verify-deployment.sh" "${STAGE}/scripts/"

	# The built front end travels with the release. A missing build is not an
	# error: the gateway serves a placeholder explaining how to produce it, so
	# a backend-only deployment still works.
	if [ -f "${ROOT}/src/customapi/web/dist/index.html" ]; then
		log "  including the built web UI"
		mkdir -p "${STAGE}/web"
		cp -r "${ROOT}/src/customapi/web/dist/." "${STAGE}/web/"
	else
		warn "the web UI has not been built; the gateway will serve a placeholder"
		warn "  build it with: cd src/customapi/web && npm ci && npm run build"
	fi
	for f in "${ROOT}"/docs/*.md; do
		[ -f "$f" ] && cp "$f" "${STAGE}/docs/"
	done

	cat > "${STAGE}/RELEASE" <<EOF
component: customapi-customs
version:   ${VERSION}
commit:    ${COMMIT}
built:     ${BUILT}
target:    ${GOOS_TARGET}/${GOARCH_TARGET}
EOF

	# Checksums so an operator can verify a copied release.
	(cd "${STAGE}" && find . -type f ! -name SHA256SUMS -exec sha256sum {} \; | sort -k2 > SHA256SUMS)

	log "release contents:"
	(cd "${STAGE}" && find . -type f | sort | sed 's/^/  /')
}

# ---------------------------------------------------------------------------
# ship / install / test
# ---------------------------------------------------------------------------

do_ship() {
	[ -d "${STAGE}" ] || die "nothing to ship; run 'stage' first"
	require ssh
	require scp
	log "shipping ${STAGE} to ${TARGET}:${REMOTE_DIR}"
	ssh -o BatchMode=yes "${TARGET}" "rm -rf ${REMOTE_DIR} && mkdir -p ${REMOTE_DIR}" \
		|| die "cannot reach ${TARGET} over SSH; is the VM running?"
	scp -q -r "${STAGE}/." "${TARGET}:${REMOTE_DIR}/"
	log "copied $(ssh "${TARGET}" "find ${REMOTE_DIR} -type f | wc -l | tr -d ' '") files"
}

do_install() {
	log "installing on ${TARGET}"
	ssh "${TARGET}" "sudo -n sh ${REMOTE_DIR}/scripts/install.sh" \
		|| die "installation failed on ${TARGET}"
}

do_test() {
	log "running the acceptance test on ${TARGET}"
	ssh "${TARGET}" "sudo -n sh ${REMOTE_DIR}/scripts/smoke-test.sh" \
		|| die "the acceptance test reported failures"
}

# ---------------------------------------------------------------------------
# local-test
# ---------------------------------------------------------------------------

do_local_test() {
	require go
	log "go vet"
	(cd "${SRC}" && go vet ./...)
	log "go test (race detector)"
	(cd "${SRC}" && go test ./... -race -count=1)
	log "go test (coverage)"
	(cd "${SRC}" && go test ./internal/... -cover -count=1)
}

do_clean() {
	log "removing ${DIST}"
	rm -rf "${DIST}"
}

# ---------------------------------------------------------------------------

CMD=${1:-all}
if [ $# -gt 0 ]; then shift; fi
while [ $# -gt 0 ]; do
	case "$1" in
	--target) TARGET="$2"; shift 2 ;;
	--version) VERSION="$2"; STAGE="${DIST}/customapi-${VERSION}"; shift 2 ;;
	*) die "unknown option: $1" ;;
	esac
done

case "${CMD}" in
build)      do_build ;;
stage)      do_stage ;;
ship)       do_ship ;;
install)    do_install ;;
test)       do_test ;;
all)        do_build; do_stage; do_ship; do_install; do_test ;;
local-test) do_local_test ;;
clean)      do_clean ;;
*)
	sed -n '2,30p' "$0"
	exit 2
	;;
esac

log "done: ${CMD}"
