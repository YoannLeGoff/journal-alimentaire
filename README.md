# Journal alimentaire

Petit journal alimentaire en français, utilisable dans un navigateur et conçu pour un hébergement PHP sans base de données. La saisie s’ouvre par défaut en vue journalière, avec navigation entre les jours ; « Vue hebdomadaire » permet d’afficher toutes les journées en même temps. La consultation est toujours hebdomadaire et en lecture seule. Sur grand écran, les sept champs de chaque journée sont disposés en colonnes, dans cet ordre : petit-déjeuner, collation du matin, déjeuner, collation de l’après-midi, repas du soir, collation du soir et note. Sur mobile, les champs sont empilés verticalement. Pendant la saisie, toute la semaine est automatiquement enregistrée après une courte pause ; un bouton permet aussi de l’enregistrer immédiatement.

Le logo ramène à l’accueil : à la journée du jour pour une session d’édition, à la semaine en cours via un lien de partage en lecture seule, ou à la connexion si la session n’est plus autorisée.

La navigation comporte aussi un pictogramme « Journal » qui mène au même accueil et reste sélectionné dans les vues du journal.

Chaque journée affiche un score de complétion de 0 à 100 %, calculé en additionnant le poids des champs alimentaires non vides : petit-déjeuner 20 %, collation du matin 8 %, déjeuner 30 %, collation de l’après-midi 10 %, repas du soir 20 % et collation du soir 12 %. Le champ Note ne compte pas. Le score se met à jour pendant la saisie et apparaît aussi dans la vue de consultation.

La page « Rapport » affiche par défaut le mois en cours, avec une pastille cliquable pour chaque jour passé. Le sélecteur « Comparer » permet de choisir clairement 1, 2, 3 ou 4 mois ; quatre mois restent affichés pendant la navigation, qui déplace la fenêtre d’un mois à la fois. Le balayage fonctionne sur mobile et les chevrons sont disponibles sur grand écran. Le rouge correspond à un score inférieur à 60 %, l’orange à 60–89 % et le vert à 90–100 % ; les jours futurs ne sont pas cliquables. Sélectionner une pastille ouvre la journée en édition.

Depuis la page « Rapport », « Vue hebdomadaire » ouvre la semaine en cours en lecture seule. La vue hebdomadaire d’édition reste accessible depuis la saisie journalière.

PHP 7.3 ou plus récent est nécessaire.

## Installation sur l’hébergement FTP

1. Envoyez `index.php` et `JournalAlimentaire.png` dans le même dossier de votre hébergement PHP.
2. Ouvrez l’adresse correspondante dans votre navigateur et créez un mot de passe d’au moins 12 caractères dès la première visite, avant de partager l’adresse.
3. Le site crée automatiquement le dossier `journal-data` à côté de `index.php`. Le compte PHP doit pouvoir écrire dans ce dossier. Les entrées et le hash du mot de passe y sont stockés ; aucun mot de passe en clair n’est enregistré.
4. Faites des sauvegardes régulières du dossier `journal-data`.

Le dossier `journal-data` contient vos données privées. Il est exclu du dépôt Git par `.gitignore` et ne doit jamais être publié.

Le dossier de données est protégé par un fichier `.htaccess` et un index PHP générés lors du premier accès. Apache avec `mod_authz_core` (configuration habituelle des hébergements mutualisés) est requis pour bloquer l’accès direct aux fichiers de données. Si votre hébergeur utilise un autre serveur web, configurez-y une règle équivalente pour interdire l’accès HTTP à `journal-data`. Dans la mesure du possible, placez les données hors du répertoire public du site.

Activez HTTPS sur votre hébergement pour protéger le mot de passe pendant sa saisie. Pour réinitialiser le mot de passe, supprimez `journal-data/auth.php` via FTP ; le journal lui-même reste intact et un nouveau mot de passe pourra être créé à la prochaine visite.

## Lien de lecture seule

Dans votre session protégée, le bouton « Lien » dans l’en-tête copie dans le presse-papiers le lien de lecture seule déjà actif, sans le remplacer ni le révoquer. La page « Configuration », accessible par la roue dentée, regroupe la création d’un nouveau lien et sa révocation. Créer un nouveau lien remplace et révoque immédiatement le précédent. Toute personne qui possède le lien peut consulter les journaux et naviguer entre les semaines, mais ne peut pas modifier les entrées.

Le lien agit comme un mot de passe : transmettez-le uniquement à la personne voulue et seulement après avoir activé HTTPS. Dans la configuration, le lien complet n’est affiché qu’une fois lors de sa création.

Le jeton est généré de façon aléatoire. Son hash sert à vérifier les liens entrants ; le jeton actif est aussi conservé dans le fichier de configuration protégé afin que le bouton « Lien » puisse le recopier sans le modifier. Protégez et sauvegardez ce fichier comme un secret. Les pages ouvertes par lien secret interdisent leur mise en cache et l’envoi du lien comme référent à d’autres pages. Un lien envoyé ou copié par erreur doit être révoqué puis remplacé.

Sur une installation mise à jour qui contient déjà un lien créé par une ancienne version, seul le hash du jeton existe : il est impossible de reconstituer le lien. Créez une fois un nouveau lien depuis « Configuration » ; le bouton « Lien » pourra ensuite recopier ce lien sans le révoquer.

## Validation des champs

Les champs acceptent les lettres, chiffres, espaces et une liste limitée de ponctuation utile à la saisie alimentaire. Les symboles courants de code/HTML et les instructions SQL reconnaissables sont refusés par la validation serveur ; les données restent en outre échappées lors de l’affichage. L’application ne possède pas de base de données et n’exécute pas le contenu saisi comme code ou requête. Les quantités comme `2 œufs, 150 g` restent autorisées.

L’enregistrement automatique nécessite JavaScript et une connexion active. Le statut indique si les modifications sont en attente, en cours ou enregistrées ; en cas de coupure, un avertissement s’affiche avant de quitter la page. Sans JavaScript, le bouton « Enregistrer » de chaque journée continue de sauvegarder cette journée manuellement.
