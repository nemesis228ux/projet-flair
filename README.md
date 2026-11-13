# Flair

Flair est un outil web stateless d'aide à la détection des arnaques en ligne.

## Supervision et déploiement

La supervision ne nécessite pas de base de données applicative. Le backend
expose des métriques agrégées sur `GET /metrics` (nombre de requêtes, codes
HTTP et latences). Prometheus les collecte périodiquement et conserve cette
série temporelle dans son volume Docker. Grafana lit Prometheus et fournit les
tableaux de bord. Aucun contenu d'URL, d'e-mail ou de mot de passe n'est
enregistré par cette chaîne.

Le stack Docker comprend :

- le backend FastAPI sur `http://localhost:8000` ;
- le frontend Nginx sur `http://localhost:8080` ;
- Prometheus sur `http://localhost:9090` ;
- Grafana sur `http://localhost:3000`.

Depuis la racine du projet :

```powershell
docker compose up --build
```

### Quel fichier `.env` utiliser ?

Il y a trois fichiers d'exemple parce que l'application peut être lancée de
deux façons :

1. **Docker Compose** : copiez [.env.example](./.env.example) en `.env` à la
   racine. C'est le seul fichier nécessaire pour `docker compose up`.
2. **Backend seul en développement** : copiez
   [backend/.env.example](./backend/.env.example) en `backend/.env`, puis
   lancez FastAPI depuis `backend/`.
3. **Frontend seul en développement** : copiez
   [frontend/.env.example](./frontend/.env.example) en `frontend/.env`, puis
   lancez Vite depuis `frontend/`.

Les fichiers `.env` contiennent les valeurs locales et ne sont jamais commités.
Les fichiers `.env.example` ne contiennent aucun secret : ils servent
uniquement de modèles documentés. Pour Docker, n'utilisez pas `backend/.env` et
`frontend/.env` simultanément : utilisez seulement le `.env` à la racine.

Le compte Grafana est défini par `GRAFANA_ADMIN_USER` et
`GRAFANA_ADMIN_PASSWORD` dans le `.env` racine. En déploiement, définissez au
minimum `GRAFANA_ADMIN_PASSWORD`, `GEMINI_API_KEY`, `ALLOWED_ORIGINS` et
`VITE_API_URL` et `METRICS_TOKEN` dans l'environnement avant de lancer
Compose. `METRICS_TOKEN` doit être une valeur aléatoire longue et identique
entre le backend et Prometheus. Les volumes
`prometheus-data` et `grafana-data` conservent uniquement les données de
supervision et la configuration Grafana.

### Déploiement

Pour un déploiement Docker sur un VPS, le fichier `.env` racine est utilisé par
Compose et `.metrics_token` contient le même token que `METRICS_TOKEN`. Ces
deux fichiers restent privés et ne sont jamais commités.

Pour Render, configurez au minimum `GEMINI_API_KEY`, `GEMINI_MODEL`,
`ALLOWED_ORIGINS` et `METRICS_TOKEN` dans les variables secrètes du service
backend. Grafana Cloud est alors le service de supervision externe ; il faut
configurer sa collecte Prometheus avec l'URL publique du backend, le chemin
`/metrics` et l'en-tête `Authorization: Bearer <METRICS_TOKEN>`. Le token ne
doit jamais être placé dans le frontend ou dans une variable `VITE_*`.