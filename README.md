# Flair

Flair est une application web qui aide à repérer les arnaques en ligne avant
d'agir. Elle propose une vérification simple de liens, d'e-mails et de mots de
passe, sans compte utilisateur et sans conserver les contenus soumis.

## Fonctionnalités

- analyse d'URL : signaux de phishing, redirections, domaines suspects et
  obfuscation ;
- analyse d'e-mail : indices de manipulation, demandes sensibles et liens
  intégrés ;
- vérification de mot de passe : estimation de robustesse et recherche
  confidentielle dans les fuites connues ;
- interface en français et en anglais ;
- thème clair et sombre, adaptée au mobile et au bureau.

Flair est une aide à la décision et ne garantit pas qu'un contenu est sûr.

## Démo

Site web : [flair-jade.vercel.app](https://flair-jade.vercel.app)

## Auteur

Projet réalisé par **Ali Barry**.

## Licence

Ce projet est distribué sous licence [MIT](./LICENSE).

## Documentation technique

- [Architecture backend](./backend/docs/architecture.md)
- [Conventions backend](./backend/docs/backend-conventions.md)
- [Architecture frontend](./frontend/docs/architecture.md)

## Développement local

Les instructions de démarrage et les modèles de variables d'environnement se
trouvent dans les dossiers [backend](./backend) et [frontend](./frontend).
Les fichiers `.env` locaux ne doivent jamais être commités.
