# FastAPI Starter

Structure de depart reutilisable, inspiree de l'architecture du projet source.
Elle contient les couches applicatives et les reponses standardisees, mais
n'inclut ni connexion a une base de donnees, ni ORM, ni authentification, ni
migrations.

## Architecture

```text
app/
  common/
    constants/          Messages, tags et noms de services
    utils/              Utilitaires partages
    app_result.py       Resultat generique succes/echec
    business_error.py   Erreurs metier standardisees
  core/
    config.py           Configuration generale
    logging_config.py   Configuration des logs
  repositories/
    helpers/
      repositories_utils.py  Traitement generique des erreurs de repository
    __init__.py          Resultats CRUD et conversion vers les services
  routers/
    v1/
      base_router.py     Route de verification
      example_router.py  Exemple de reponse API standardisee
  schemas/
    shared/
      api_base_response.py    Format API success/result/error
      utils_schemas.py        GlobalStringResponse et StringMessage
      pagination_schemas.py   Structures de pagination
  services/
    __init__.py          Resultats de service et conversion HTTP
  settings/
    app_lifespan.py     Cycle de vie sans initialisation de base de donnees
    cors.py              Configuration CORS
  main.py                Point d'entree FastAPI
tests/
docs/
```

Les nouveaux modules metier se creent dans `routers/v1`, `schemas`,
`services` et `repositories`. Le repository starter n'impose pas de technologie
de persistance : les repositories peuvent appeler un service externe, un fichier
ou une base de donnees ajoutee plus tard.

## Reponses partagees

Les services retournent `ServiceResult`, convertissable en `ApiBaseResponse`
avec le statut HTTP correspondant. Pour une operation qui renvoie seulement
un message, utilisez `GlobalStringResponse` et `StringMessage`. L'endpoint
`GET /api/v1/examples/message` illustre ce flux.

Les repositories peuvent retourner `CrudResult`; l'echec se convertit vers un
resultat de service avec `to_service_error()`. Le helper generique de
`repositories/helpers/repositories_utils.py` journalise les exceptions et
produit une erreur interne sans rollback ni dependance DB.

## Demarrage (Windows)

Depuis le dossier `fastapi_starter` :

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload
```

- Documentation interactive : <http://127.0.0.1:8000/docs>
- Verification : `GET /api/v1/health`

Les parametres `APP_NAME`, `APP_VERSION`, `API_PREFIX`, `API_HOST`, `API_PORT`
et `CORS_ORIGINS` (origines separees par des virgules) peuvent etre fournis
comme variables d'environnement.
