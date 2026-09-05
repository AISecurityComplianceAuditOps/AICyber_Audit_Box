#!/bin/sh
# Offline installer -- AICyberAuditBox.
#
# Loads every image from the single images tar beside this script, then starts
# the stack. Nothing is downloaded: the machine never needs to reach a registry,
# which is the point of an air-gapped install.
set -e

VERSION="__VERSION__"
IMAGES="aicyberauditbox-images-${VERSION}.tar"
COMPOSE="docker-compose.yml"

echo "==========================================================="
echo "  AICyberAuditBox ${VERSION} -- offline install"
echo "==========================================================="

if ! docker info >/dev/null 2>&1; then
  echo "ERROR: Docker is not running. Start Docker Desktop (or dockerd) first."
  exit 1
fi
if [ ! -f "$IMAGES" ]; then
  echo "ERROR: $IMAGES is not in this folder. Run the installer from the"
  echo "       folder the bundle extracted into."
  exit 1
fi

echo ""
echo "--> Loading all images from $IMAGES"
echo "    (__SIZE__; several minutes, and it prints nothing while it works)"
docker load -i "$IMAGES"

echo ""
echo "--> Verifying every image the stack needs is present"
MISSING=0
for i in aicyberauditbox-app:${VERSION} \
         aicyberauditbox-llm:${VERSION} \
         aicyberauditbox-llm-embed:${VERSION} \
         aicyberauditbox-shakthidb:3.10 \
         redis:7-alpine; do
  if docker image inspect "$i" >/dev/null 2>&1; then
    echo "    ok   $i"
  else
    echo "    MISSING  $i"
    MISSING=1
  fi
done
[ "$MISSING" = "0" ] || { echo "Aborting: the images above did not load."; exit 1; }

echo ""
echo "--> Starting the stack"
docker compose -f "$COMPOSE" up -d

echo ""
echo "--> Waiting for the application to answer (up to 5 minutes)"
i=0
while [ $i -lt 100 ]; do
  # -f makes curl exit non-zero on any HTTP error, so a zero exit IS the
  # readiness signal. Parsing %{http_code} was fragile: when curl failed for an
  # unrelated reason it had already printed a partial code, and the "|| echo 000"
  # fallback appended to it -- yielding a value that could never match, so a
  # perfectly working app reported as a failed install.
  if curl -fs --max-time 5 http://localhost:8000/ >/dev/null 2>&1; then
    # The app answering is not the whole story. The LLM is a separate container
    # and the app comes up perfectly well without it, so an LLM that refused to
    # start -- nearly always too little memory for the selected model -- used to
    # end with this script printing "Ready" and the customer discovering the
    # truth one failed audit at a time, on a machine with no internet to ask
    # about it. Check it here and show the reason it gave.
    #
    # .State.Running alone is not enough. The service is restart: always, so a
    # container that refuses to start flaps -- and an inspect that lands during
    # one of those moments reports Running=true, which is how this check first
    # passed over an LLM that was crash-looping on every attempt. RestartCount
    # is the durable signal: a container that came up cleanly has never
    # restarted, and a looping one has restarted several times by the time the
    # app has finished answering.
    LLM_CID=$(docker compose -f "$COMPOSE" ps -aq llm 2>/dev/null)
    LLM_STATE=$(docker inspect -f '{{.State.Status}}' "$LLM_CID" 2>/dev/null || echo missing)
    LLM_RESTARTS=$(docker inspect -f '{{.RestartCount}}' "$LLM_CID" 2>/dev/null || echo 0)
    if [ "$LLM_STATE" != "running" ] || [ "$LLM_RESTARTS" -gt 0 ] 2>/dev/null; then
      echo ""
      echo "==========================================================="
      echo "  The application is up, but the LLM is NOT healthy."
      echo "==========================================================="
      echo ""
      echo "  llm container state: ${LLM_STATE}, restarts: ${LLM_RESTARTS}"
      echo ""
      echo "  It reported:"
      docker compose -f "$COMPOSE" logs --tail 25 llm 2>/dev/null | sed 's/^/    /'
      echo ""
      echo "  Audits cannot run until this is resolved."
      echo "  See INSTALL_v${VERSION}.md, section 6 (choosing the model)."
      exit 1
    fi
    echo ""
    echo "==========================================================="
    echo "  Ready.  Open http://localhost:8000/"
    echo "==========================================================="
    echo ""
    echo "Confirm the LLM sized itself correctly for this machine:"
    echo "  docker compose -f $COMPOSE logs llm | grep 'LLM ENTRYPOINT'"
    echo ""
    echo "The last line must read '= 32768 tokens per request'. A lower number"
    echo "means the machine has less RAM than the LLM expected, and evidence"
    echo "would be truncated before the model sees it -- see INSTALL_v${VERSION}.md."
    exit 0
  fi
  i=$((i + 1))
  sleep 3
done

echo "The app did not answer in time. Check:"
echo "  docker compose -f $COMPOSE ps"
echo "  docker compose -f $COMPOSE logs app | tail -40"
exit 1
