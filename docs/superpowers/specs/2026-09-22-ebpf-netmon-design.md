# ebpf-netmon — Design

## Objectif

Agent d'observabilité réseau bas niveau : mesure la latence de connexion TCP,
les retransmissions et le débit, attribués par processus (PID), via des
sondes eBPF attachées au stack TCP du noyau Linux. Les métriques sont
exposées au format Prometheus et visualisées dans Grafana.

Projet de portfolio ciblant des postes systèmes/réseau et infra/plateforme :
démontre la maîtrise du noyau Linux, des protocoles réseau et de
l'observabilité moderne (eBPF), au-delà d'un usage applicatif classique de
Kubernetes/Docker.

## Environnement cible

- Développement et exécution : Linux (kernel ≥ 5.8 pour BTF/CO-RE), via WSL2
  sur la machine de dev.
- Le poste de dev actuel n'a pas WSL correctement installé
  (`wsl.exe` renvoie `REGDB_E_CLASSNOTREG`) — prérequis avant toute
  compilation/test réels, documenté dans le README (`wsl --install`, puis
  activer les features Windows "Windows Subsystem for Linux" et
  "Virtual Machine Platform", redémarrer).

## Architecture

```
Kernel space (eBPF, C)          Userspace (Go)              Observabilité
┌─────────────────────┐        ┌──────────────────┐        ┌────────────┐
│ kprobe/tcp_connect   │        │                  │        │            │
│ kprobe/tcp_close     │  maps  │  agent           │  HTTP  │ Prometheus │
│ kprobe/tcp_retransmit│ ─────► │  (bpf2go +       │ ─────► │  → Grafana │
│   _skb               │        │   cilium/ebpf)   │/metrics│            │
│ kprobe/tcp_sendmsg   │        │                  │        │            │
│ kprobe/tcp_recvmsg   │        └──────────────────┘        └────────────┘
└─────────────────────┘
```

### Composants

1. **`bpf/`** — programmes eBPF en C restreint (un fichier par sonde),
   compilés en objets BPF via clang. Chaque sonde écrit dans une BPF map
   (`BPF_MAP_TYPE_HASH`), clé = struct `{pid, saddr, daddr, sport, dport}`,
   valeur = struct de compteurs (bytes_sent, bytes_recv, retransmits,
   connect_latency_ns).

2. **`agent/`** — binaire Go :
   - `main.go` : cycle de vie (charge les probes, boucle de collecte, serveur HTTP)
   - `collector/` : lecture périodique des BPF maps, agrégation, reset des compteurs
   - `procresolve/` : résolution PID → nom de process (lecture `/proc/<pid>/comm`,
     avec cache et gestion de l'expiration si le process meurt)
   - `metrics/` : définition et mise à jour des métriques Prometheus
     (`client_golang`)
   - Génération des bindings Go via `bpf2go` (partie de `cilium/ebpf`) à partir
     des objets compilés dans `bpf/`

3. **`deploy/`** — `docker-compose.yml` (Prometheus + Grafana), config
   Prometheus (scrape de l'agent), dashboard Grafana préconfiguré (JSON)
   montrant : débit par process, latence de connexion (histogramme),
   retransmissions dans le temps.

## Flux de données

1. Un événement TCP survient (connexion, envoi/réception de données,
   retransmission) → la sonde eBPF correspondante s'exécute dans le contexte
   du process courant, met à jour la BPF map.
2. Toutes les 5 secondes, l'agent Go lit l'intégralité de chaque map,
   agrège les valeurs par PID, résout le nom de process, met à jour les
   métriques Prometheus, puis **remet à zéro les compteurs lus** (évite
   l'overflow des maps et donne des métriques en delta par intervalle).
3. Prometheus scrape `/metrics` toutes les 15s ; Grafana interroge Prometheus.

## Gestion des erreurs

- Si une sonde échoue à s'attacher (kernel trop ancien, permissions
  insuffisantes) : log de l'erreur avec le nom de la sonde, l'agent continue
  avec les sondes qui ont réussi plutôt que de crasher.
- Si `/proc/<pid>/comm` n'existe plus (process terminé entre l'événement et
  la résolution) : le process est étiqueté `unknown (pid <N>)` plutôt que de
  faire échouer la collecte.
- Erreurs de lecture de map (rare, ex: map détruite) : log + skip de cet
  intervalle de collecte, pas de crash de l'agent.

## Tests

- **Unitaires (Go, sans noyau réel)** : logique d'agrégation (`collector`),
  résolution PID→nom avec cache (`procresolve`), formatage des métriques —
  toutes mockables via interfaces sur la lecture des maps et de `/proc`.
- **Intégration (nécessite Linux + CAP_BPF, exécuté sous WSL2)** : script qui
  génère du trafic TCP connu (client/serveur local), lance l'agent, et
  vérifie via l'endpoint `/metrics` que les compteurs correspondent au
  trafic généré (± tolérance).
- Pas de tests qui nécessitent un vrai environnement de prod multi-hôtes —
  hors scope du MVP.

## Hors scope (MVP)

- Support UDP (TCP uniquement pour le MVP)
- Multi-hôtes avec agrégation centrale (un agent = une machine, exposée
  localement à Prometheus)
- Alerting (Grafana/Prometheus alerting existant suffit, pas de logique custom)
- IPv6 (IPv4 uniquement pour le MVP, structuré pour extension future)
