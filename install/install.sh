#!/bin/sh
# fwd installer — build-from-source, single-host FTSO provider signing stack.
#
#   curl -sfL https://get.proofs.africa/fwd | sh -                                              # install INERT (signs nothing)
#   curl -sfL https://get.proofs.africa/fwd | sh -s -- --with-clif                              # + clif claim/FSP layer (still inert)
#   curl -sfL https://get.proofs.africa/fwd | sh -s -- --onboard-rewards --identity 0x.. --recipient 0x..  # install + guided onboarding
#
# Builds the image from pinned source locally (no registry, no prebuilt-binary
# trust), brings the stack up inert (empty default-deny policy, signs nothing), then
# prints the onboarding command. Onboarding is opt-in via --onboard-rewards (requires
# a TTY + a started stack): the wizard narrates each step and PASTES your key(s)
# directly (hidden); the custodial acts (your key, the on-chain authorization) stay
# yours. Install always ends inert so it is safe to run headless or in CI.
#
# Re-runnable: preserves an existing master.key / .env / policy.yaml.
#
# Config (env or flags), k3s-style:
#   FWD_DIR=/opt/fwd            install root        (--dir)
#   FWD_BIN_DIR=/usr/local/bin  host wrapper dir
#   FWD_REPO=https://github.com/africanproofs/fwd.git
#   FWD_REF=main               git ref to build    (--ref; a release pins a tag)
#   FWD_SHA=                    if set, the cloned HEAD must equal it (integrity pin)
#   FWD_IMAGE_TAG=local         built image tag
#   CLIF_REPO / CLIF_REF        (--with-clif; clif must be public)
#   onboarding (opt-in): --onboard-rewards  --identity 0xOWNER  --recipient 0xADDR  --networks LIST(=songbird)  --import-existing
#   (--inert is accepted as a deprecated no-op — inert is now the default)
#   flags: --with-clif --no-start --no-build --production --dir DIR --ref REF --help
set -eu

FWD_DIR="${FWD_DIR:-/opt/fwd}"
FWD_BIN_DIR="${FWD_BIN_DIR:-/usr/local/bin}"
FWD_REPO="${FWD_REPO:-https://github.com/africanproofs/fwd.git}"
FWD_REF="${FWD_REF:-main}"
FWD_SHA="${FWD_SHA:-}"
FWD_IMAGE_TAG="${FWD_IMAGE_TAG:-local}"
FWD_CONTAINER="${FWD_CONTAINER:-fwd}"
CLIF_REPO="${CLIF_REPO:-https://github.com/africanproofs/clif.git}"
CLIF_REF="${CLIF_REF:-main}"
WITH_CLIF=0
START=1
BUILD=1
MODE=dev
ONBOARD_REWARDS=0
IDENTITY=""
RECIPIENT=""
ONB_NETWORKS=songbird
IMPORT_EXISTING=0

log()  { printf '\033[1;33m[fwd-install]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[fwd-install] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

while [ "$#" -gt 0 ]; do
  case "$1" in
    --with-clif)   WITH_CLIF=1 ;;
    --no-start)    START=0 ;;
    --no-build)    BUILD=0 ;;
    --production)  MODE=production ;;
    --dev)         MODE=dev ;;
    --dir)         shift; FWD_DIR="${1:?--dir needs a value}" ;;
    --ref)         shift; FWD_REF="${1:?--ref needs a value}" ;;
    --onboard-rewards) ONBOARD_REWARDS=1 ;;
    --inert)           log "--inert is now the default (install ends inert); onboarding is opt-in via --onboard-rewards — accepted as a no-op" ;;
    --identity)        shift; IDENTITY="${1:?--identity needs a value}" ;;
    --recipient)       shift; RECIPIENT="${1:?--recipient needs a value}" ;;
    --networks)        shift; ONB_NETWORKS="${1:?--networks needs a value}" ;;
    --import-existing) IMPORT_EXISTING=1 ;;
    -h|--help)
      sed -n '2,/^set -eu/p' "$0" | sed -e '$d' -e 's/^# \{0,1\}//'
      exit 0 ;;
    *) die "unknown argument: $1 (try --help)" ;;
  esac
  shift
done

# --- 1. preflight ---------------------------------------------------------
log "preflight"
have docker || die "docker not found — install Docker Engine first"
docker compose version >/dev/null 2>&1 || die "docker compose v2 not found (need the 'docker compose' plugin)"
have git || die "git not found — needed to fetch pinned source (build-from-source)"
docker info >/dev/null 2>&1 || die "cannot talk to the Docker daemon (is it running? permissions?)"
log "host ok: docker + compose v2 + git; mode=$MODE dir=$FWD_DIR"

# --- 2. fetch pinned source ----------------------------------------------
mkdir -p "$FWD_DIR"
SRC="$FWD_DIR/src"
if [ -d "$SRC/.git" ]; then
  log "source present at $SRC — fetching $FWD_REF"
  git -C "$SRC" fetch --depth 1 origin "$FWD_REF" >/dev/null 2>&1 || die "git fetch failed"
  git -C "$SRC" checkout -q FETCH_HEAD
else
  log "cloning $FWD_REPO @ $FWD_REF -> $SRC"
  git clone --depth 1 --branch "$FWD_REF" "$FWD_REPO" "$SRC" 2>/dev/null \
    || git clone "$FWD_REPO" "$SRC" 2>/dev/null \
    || die "git clone failed: $FWD_REPO"
  [ "$FWD_REF" = main ] || git -C "$SRC" checkout -q "$FWD_REF" 2>/dev/null || true
fi
if [ -n "$FWD_SHA" ]; then
  got="$(git -C "$SRC" rev-parse HEAD)"
  [ "$got" = "$FWD_SHA" ] || die "integrity pin mismatch: HEAD=$got expected=$FWD_SHA"
  log "integrity pin ok ($FWD_SHA)"
fi

if [ "$WITH_CLIF" -eq 1 ]; then
  CLIF_SRC="$FWD_DIR/clif"
  if [ -d "$CLIF_SRC/.git" ]; then
    git -C "$CLIF_SRC" fetch --depth 1 origin "$CLIF_REF" >/dev/null 2>&1 && git -C "$CLIF_SRC" checkout -q FETCH_HEAD || true
  else
    log "cloning clif $CLIF_REPO @ $CLIF_REF -> $CLIF_SRC"
    git clone --depth 1 --branch "$CLIF_REF" "$CLIF_REPO" "$CLIF_SRC" 2>/dev/null \
      || die "git clone failed: $CLIF_REPO (clif must be public for --with-clif)"
  fi
  # clif's compose service defs reference an env_file; compose validates it even
  # for the (stopped) clif daemons. Seed a placeholder from .env.example so the
  # merged compose parses — the operator fills in real values (NETWORK, the fwd
  # caller tokens, wallet names) during onboarding before starting the daemons.
  [ -f "$CLIF_SRC/.env" ] || { [ -f "$CLIF_SRC/.env.example" ] && cp "$CLIF_SRC/.env.example" "$CLIF_SRC/.env" && log "seeded placeholder $CLIF_SRC/.env (fill in during onboarding)"; }
fi

# --- 3. config: .env (admin key) + inert default-deny policy --------------
# Co-located in the compose dir ($SRC), where docker-compose.yml resolves
# `env_file: .env` and the `./config/*` mounts (gitignored — preserved across
# the re-fetch/upgrade `git checkout`).
mkdir -p "$SRC/config"
ENV_FILE="$SRC/.env"
if [ ! -f "$ENV_FILE" ]; then
  admin="$(od -An -tx1 -N24 /dev/urandom | tr -d ' \n')"
  umask 077
  {
    echo "# fwd runtime config (generated by install.sh; preserved on re-run)."
    echo "FWD_ADMIN_KEY=$admin"
    echo "FWD_IMAGE_TAG=$FWD_IMAGE_TAG"
  } > "$ENV_FILE"
  log "wrote $ENV_FILE (generated FWD_ADMIN_KEY)"
else
  log "preserving existing $ENV_FILE"
fi

POLICY="$SRC/config/policy.yaml"
if [ ! -f "$POLICY" ]; then
  cat > "$POLICY" <<'YAML'
# fwd INERT default-deny policy (installed). Empty on purpose — fwd signs
# NOTHING until you author real rules. Generate yours:
#   clifwd policy init --networks flare,songbird --recipient 0xYOURADDR --out config/policy.yaml
#   clifwd policy validate
version: 1
YAML
  log "wrote inert default-deny $POLICY"
else
  log "preserving existing $POLICY"
fi

# --- 4. build the image from source --------------------------------------
COMPOSE="-f $SRC/docker-compose.yml"
[ "$WITH_CLIF" -eq 1 ] && COMPOSE="$COMPOSE -f $SRC/docker-compose.clif.yml"
export FWD_IMAGE_TAG FWD_CONTAINER CLIF_SRC="${FWD_DIR}/clif" CLIF_ENV="${FWD_DIR}/clif/.env"
if [ "$BUILD" -eq 1 ]; then
  log "building image(s) from source (this is the slow first step)"
  ( cd "$SRC" && env FWD_IMAGE_TAG="$FWD_IMAGE_TAG" docker compose $COMPOSE build ) || die "docker compose build failed"
else
  log "--no-build: skipping image build"
fi

# --- 5. custody: generate the sealed master locally (never transmitted) ----
MASTER="$SRC/config/master.key"
if [ ! -f "$MASTER" ]; then
  if [ "$BUILD" -eq 1 ]; then
    log "generating sealed master (local, mode 0600)"
    docker run --rm -v "$SRC/config:/out" \
      "registry.gitlab.com/proofs.africa/fwd/fwd:${FWD_IMAGE_TAG}" \
      clifwd master generate --out /out/master.key >/dev/null \
      || die "master generate failed"
    [ -f "$MASTER" ] || die "master.key not produced"
    log "sealed master written to $MASTER"
  else
    log "--no-build: skipping master generation (no image to run clifwd)"
  fi
else
  log "preserving existing sealed master $MASTER"
fi

# --- 6. install host wrappers --------------------------------------------
if [ -d "$FWD_BIN_DIR" ] && [ -w "$FWD_BIN_DIR" ]; then
  install -m 0755 "$SRC/install/fwd" "$FWD_BIN_DIR/fwd"
  install -m 0755 "$SRC/install/clifwd" "$FWD_BIN_DIR/clifwd"
  install -m 0755 "$SRC/install/clif" "$FWD_BIN_DIR/clif"
  # Bake the compose-bundle dir ($SRC) into the wrappers' FWD_DIR default
  # (`fwd` for compose ops; `clifwd`/`fwd` for `onboard` routing -> $SRC/install/onboard).
  for _w in fwd clifwd clif; do
    sed -i "s#\${FWD_DIR:-/opt/fwd}#\${FWD_DIR:-$SRC}#" "$FWD_BIN_DIR/$_w" 2>/dev/null || true
  done
  # clif's source + per-network .env live at the install ROOT ($FWD_DIR/clif),
  # a SIBLING of the compose dir ($SRC) — bake the absolute path so the wrappers
  # resolve clif's build context + env_file correctly (they run compose from $SRC).
  for _w in fwd clifwd clif; do
    sed -i "s#\${CLIF_SRC:-/opt/fwd/clif}#\${CLIF_SRC:-$FWD_DIR/clif}#" "$FWD_BIN_DIR/$_w" 2>/dev/null || true
  done
  log "installed host wrappers: $FWD_BIN_DIR/{fwd,clifwd,clif}"
else
  log "NOTE: $FWD_BIN_DIR not writable — skipping host wrappers (use: docker exec $FWD_CONTAINER clifwd ...)"
fi

# --- 7. start (unless --no-start) ----------------------------------------
if [ "$START" -eq 1 ]; then
  [ "$BUILD" -eq 1 ] || die "--no-build with start: nothing to start (build first)"
  log "starting fwd (inert) ..."
  ( cd "$SRC" && docker compose $COMPOSE up -d fwd litestream ) \
    || die "docker compose up failed"
  log "waiting for health ..."
  i=0; while [ "$i" -lt 20 ]; do
    st="$(docker inspect -f '{{.State.Health.Status}}' "$FWD_CONTAINER" 2>/dev/null || echo starting)"
    [ "$st" = healthy ] && break
    i=$((i+1)); sleep 3
  done
  docker exec "$FWD_CONTAINER" clifwd health || die "health check failed"
else
  log "--no-start: staged but not started. Start later with:  sudo fwd start"
fi

# --- 8. onboard by default, or stop at the custody gate (--inert / headless) ---
printf '\n\033[1;32mfwd is installed.\033[0m  Runtime: %s.\n' \
  "$( [ "$START" -eq 1 ] && echo healthy || echo 'staged (not started)' )"

ONBOARD=0
if [ "$ONBOARD_REWARDS" -eq 1 ] && [ "$START" -eq 1 ] && { true >/dev/tty; } 2>/dev/null; then
  ONBOARD=1
fi

if [ "$ONBOARD" -eq 1 ]; then
  log "running guided reward onboarding (--onboard-rewards)"
  set -- rewards --networks "$ONB_NETWORKS"
  [ -n "$IDENTITY" ]  && set -- "$@" --identity "$IDENTITY"
  [ -n "$RECIPIENT" ] && set -- "$@" --recipient "$RECIPIENT"
  [ "$IMPORT_EXISTING" -eq 1 ] && set -- "$@" --import-existing
  if FWD_DIR="$SRC" FWD_CONTAINER="$FWD_CONTAINER" CLIF_SRC="$CLIF_SRC" CLIF_ENV="$CLIF_ENV" "$SRC/install/onboard" "$@"; then
    :
  else
    log "onboarding did not finish — re-run: sudo fwd onboard rewards --identity 0xOWNER --recipient 0xRECIP --networks $ONB_NETWORKS"
  fi
else
  _clif_note=""
  [ "$WITH_CLIF" -eq 1 ] && _clif_note="  (with --with-clif: onboarding also writes clif's per-network .env files and seeds each sender's nonce from chain truth via clif; then: sudo fwd start)"
  cat <<EOF

fwd is installed and running ($( [ "$START" -eq 1 ] && echo 'inert: signs NOTHING — empty default-deny policy, zero wallets' || echo 'staged, not started' )).
Custody is not initialized. To set up reward signing + fee claiming:

  sudo fwd onboard rewards --identity 0xYOUR_IDENTITY --recipient 0xYOUR_RECIPIENT --networks $ONB_NETWORKS
$_clif_note
(idempotent; narrates each step; ends with the on-chain authorization you do offline.)
Migrating an existing provider? add --import-existing.
FSP signing needs your key registered as a voter on the chosen network (Songbird/Flare for AP;
coston2 only if you are a registered Coston2 voter). Full detail: docs/one-command-install.md
EOF
fi
