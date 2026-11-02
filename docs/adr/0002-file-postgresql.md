# ADR-0002 — File d'exécution dans PostgreSQL

**Statut** : accepté (phase 1)

## Contexte
Il faut une file persistante, avec reprise après crash, priorités et contrôle de concurrence. Les
volumes sont faibles (quelques milliers de jobs par jour au plus).

## Options
1. Broker dédié (RabbitMQ, Kafka, Redis Streams) — un service de plus à sécuriser, sauvegarder et
   superviser.
2. Spring Batch / Quartz en cluster — tables et concepts supplémentaires.
3. **Table `scan_job` + `SELECT … FOR UPDATE SKIP LOCKED`** — transactionnelle avec les résultats.

## Décision
Option 3. Index partiel sur les jobs `QUEUED`, index unique partiel « un job actif par
(dépôt, branche) », bail (`lease_expires_at`) renouvelé par le worker, remise en file à expiration
jusqu'à `max_attempts`. Les alertes utilisent le même principe (outbox `webhook_delivery`).

## Conséquences
+ Aucune brique supplémentaire ; cohérence transactionnelle job ↔ findings ↔ alertes.
− Sondage périodique (quelques secondes de latence, acceptable) ; à revoir au-delà de ~100 000
  jobs/jour.
