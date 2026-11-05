#!/usr/bin/env bash
# Checks the SQL of the scan engine (backend/saytu-app/.../scan/ScanSql.java) on a throw-away PostgreSQL
# built from the Flyway migrations. Needs javac, python3 and the PostgreSQL server binaries.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MIGRATIONS="$ROOT/backend/saytu-app/src/main/resources/db/migration"
if [[ -z "${PG_BIN:-}" ]]; then PG_BIN="$(ls -d /usr/lib/postgresql/*/bin 2>/dev/null | sort -V | tail -1 || true)"; fi
[[ -x "$PG_BIN/initdb" ]] || { echo "initdb not found; set PG_BIN" >&2; exit 2; }
RUN_AS=(); [[ "$(id -u)" == "0" ]] && RUN_AS=(runuser -u postgres --)

WORK="$(mktemp -d)"; chmod 755 "$WORK"; [[ ${#RUN_AS[@]} -gt 0 ]] && chown postgres "$WORK"
PORT="${PG_PORT:-55433}"
cleanup() { "${RUN_AS[@]}" "$PG_BIN/pg_ctl" -D "$WORK/data" -m immediate stop >/dev/null 2>&1 || true; rm -rf "$WORK"; }
trap cleanup EXIT

# 1. SQL constants -> JSON (ScanSql has no dependency, it compiles alone)
mkdir -p "$WORK/classes"
javac -d "$WORK/classes" "$ROOT/backend/saytu-app/src/main/java/com/saytu/app/scan/ScanSql.java"
cat > "$WORK/Dump.java" <<'JAVA'
import java.lang.reflect.*;
public class Dump { public static void main(String[] a) throws Exception {
  Class<?> c = Class.forName("com.saytu.app.scan.ScanSql"); StringBuilder sb = new StringBuilder("{"); boolean first = true;
  for (Field f : c.getDeclaredFields()) { if (!Modifier.isStatic(f.getModifiers()) || f.getType() != String.class) continue;
    f.setAccessible(true); String v = (String) f.get(null); if (!first) sb.append(','); first = false;
    sb.append('"').append(f.getName()).append("\":\"")
      .append(v.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n")).append('"'); }
  System.out.println(sb.append('}')); } }
JAVA
javac -cp "$WORK/classes" -d "$WORK/classes" "$WORK/Dump.java"
java -cp "$WORK/classes" Dump 2>/dev/null > "$WORK/sql.json"

# 2. database with the migrations
"${RUN_AS[@]}" "$PG_BIN/initdb" -D "$WORK/data" -U saytu --auth=trust -E UTF8 >/dev/null
"${RUN_AS[@]}" "$PG_BIN/pg_ctl" -D "$WORK/data" -o "-p $PORT -k $WORK -c listen_addresses=''" -l "$WORK/pg.log" -w start >/dev/null
PSQL=("${RUN_AS[@]}" "$PG_BIN/psql" -h "$WORK" -p "$PORT" -U saytu -d postgres -q -X)
for f in $(ls "$MIGRATIONS"/V*__*.sql | sort -V); do "${PSQL[@]}" -v ON_ERROR_STOP=1 -f "$f" >/dev/null; done

# 3. lifecycle checks
python3 "$ROOT/scripts/verify-scan-sql.py" "$WORK/sql.json" "${PSQL[@]}"
