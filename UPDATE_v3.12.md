# AICyberAuditBox v3.12 - Delta Update (app)

## What's in this delivery
  1. aicyberauditbox_delta_app_v3.12.tar          -- Only the rebuilt image(s): app
  2. aicyberauditbox_delta_app_v3.12_companion.zip -- This guide + updated docker-compose.customer.yml

Postgres, Redis, and any LLM service NOT listed above are untouched and stay
running throughout this update -- this is a routine app-code or additive-schema
change (see the Rolling Update Playbook, scenarios A/B). If this delivery is for
a structural database change (renamed/dropped/retyped column), follow scenario C
instead: back up first, run the migration script, then apply this update.

## Apply this update

  Step 1 - Load only the new image(s):
    docker load -i aicyberauditbox_delta_app_v3.12.tar

  Step 2 - Replace docker-compose.customer.yml with the one in this delivery's
  companion zip (it has the new image tag already bumped for: app).

  Step 3 - Restart ONLY the updated service(s) -- everything else keeps running:
    docker compose -f docker-compose.customer.yml up -d app

  Step 4 - Confirm the schema healed (if applicable) and the app is serving:
    docker compose -f docker-compose.customer.yml logs app --tail 40
    curl -sf http://localhost:8000/ ; echo

## Rollback
Old image tags are never deleted -- to revert, edit docker-compose.customer.yml
back to the previous version tag for app, then:
    docker compose -f docker-compose.customer.yml up -d app

## Included images
- aicyberauditbox-app:3.12

## Support
Contact your AICyberAuditBox deployment team for assistance.
