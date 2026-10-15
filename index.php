<?php
declare(strict_types=1);

session_name('food_journal');
session_set_cookie_params([
    'httponly' => true,
    'secure' => isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
    'samesite' => 'Lax',
]);
session_start();
header('Referrer-Policy: no-referrer');
header('X-Robots-Tag: noindex, nofollow');

const JOURNAL_DIR = __DIR__ . DIRECTORY_SEPARATOR . 'journal-data';
const JOURNAL_FILE = JOURNAL_DIR . DIRECTORY_SEPARATOR . 'entries.json';
const AUTH_FILE = JOURNAL_DIR . DIRECTORY_SEPARATOR . 'auth.php';
const LOCK_FILE = JOURNAL_DIR . DIRECTORY_SEPARATOR . 'journal.lock';
const DAILY_SCORE_WEIGHTS = [
    'breakfast' => 20,
    'snack_morning' => 8,
    'lunch' => 30,
    'snack_afternoon' => 10,
    'evening_meal' => 20,
    'snack_evening' => 12,
    'notes' => 0,
];

final class JournalInputException extends RuntimeException
{
}

function h(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function characterCount(string $value): ?int
{
    $count = preg_match_all('/./us', $value, $matches);
    return $count === false ? null : $count;
}

function isPlainJournalText(string $value): bool
{
    $allowedCharacters = '/\A[\p{L}\p{M}\p{N}\p{Zs}\r\n\t.,;:!?()\'’"&\/+\-%€]*\z/u';
    $sqlStatement = '/\b(?:SELECT[\s\S]{0,200}\bFROM\b|INSERT\s+INTO\b|UPDATE\s+[a-z_][a-z0-9_]*\s+SET\b|DELETE\s+FROM\b|DROP\s+(?:TABLE|DATABASE)\b|ALTER\s+TABLE\b|CREATE\s+(?:TABLE|DATABASE)\b|TRUNCATE\s+TABLE\b|UNION\s+SELECT\b)/i';
    $codeStatement = '/(?:\A|\R)\s*(?:echo\b|print\b|return\b|require\b|include\b|function\b|class\b|const\b|let\b|var\b|import\b|export\b|def\b|async\b|await\b|[a-z_][a-z0-9_.]*\s*\([^)]*\)\s*;)/i';

    return preg_match($allowedCharacters, $value) === 1
        && preg_match($sqlStatement, $value) !== 1
        && preg_match($codeStatement, $value) !== 1;
}

function calculateDailyScore(array $entry): int
{
    $score = 0;

    foreach (DAILY_SCORE_WEIGHTS as $field => $weight) {
        if ($weight === 0) {
            continue;
        }
        if (isset($entry[$field]) && is_string($entry[$field]) && trim($entry[$field]) !== '') {
            $score += $weight;
        }
    }

    return $score;
}

function ensureStorage(): void
{
    if (!is_dir(JOURNAL_DIR) && !mkdir(JOURNAL_DIR, 0700, true) && !is_dir(JOURNAL_DIR)) {
        throw new RuntimeException('Impossible de créer le dossier de stockage.');
    }

    $accessFile = JOURNAL_DIR . DIRECTORY_SEPARATOR . '.htaccess';
    if (!is_file($accessFile)
        && file_put_contents($accessFile, "Require all denied\n", LOCK_EX) === false) {
        throw new RuntimeException('Impossible de protéger le dossier de stockage.');
    }

    $indexFile = JOURNAL_DIR . DIRECTORY_SEPARATOR . 'index.php';
    if (!is_file($indexFile)
        && file_put_contents($indexFile, "<?php\nhttp_response_code(404);\nexit;\n", LOCK_EX) === false) {
        throw new RuntimeException('Impossible de protéger le dossier de stockage.');
    }
}

function getPasswordHash(): ?string
{
    $auth = getAuthConfig();
    return $auth['password_hash'] ?? null;
}

function getAuthConfig(): ?array
{
    if (!is_file(AUTH_FILE)) {
        return null;
    }

    $auth = require AUTH_FILE;
    if (!is_array($auth) || !isset($auth['password_hash']) || !is_string($auth['password_hash'])) {
        throw new RuntimeException('Le fichier de configuration du mot de passe est invalide.');
    }

    if (isset($auth['share_token_hash'])
        && (!is_string($auth['share_token_hash']) || !preg_match('/\A[a-f0-9]{64}\z/', $auth['share_token_hash']))) {
        throw new RuntimeException('La configuration du lien de partage est invalide.');
    }

    if (isset($auth['share_token'])
        && (!is_string($auth['share_token'])
            || !preg_match('/\A[a-f0-9]{64}\z/', $auth['share_token'])
            || !isset($auth['share_token_hash'])
            || !hash_equals($auth['share_token_hash'], hash('sha256', $auth['share_token'])))) {
        throw new RuntimeException('La configuration du lien de partage est invalide.');
    }

    return $auth;
}

function savePasswordHash(string $hash): void
{
    $auth = getAuthConfig() ?? [];
    $auth['password_hash'] = $hash;
    saveAuthConfig($auth);
}

function saveAuthConfig(array $auth): void
{
    $code = "<?php\nreturn " . var_export($auth, true) . ";\n";
    $temporaryFile = AUTH_FILE . '.' . bin2hex(random_bytes(8)) . '.tmp';

    if (file_put_contents($temporaryFile, $code, LOCK_EX) === false) {
        throw new RuntimeException('Impossible d’enregistrer le mot de passe.');
    }

    @chmod($temporaryFile, 0600);
    if (!rename($temporaryFile, AUTH_FILE)) {
        unlink($temporaryFile);
        throw new RuntimeException('Impossible d’enregistrer le mot de passe.');
    }
}

function createShareUrl(string $token): ?string
{
    $host = $_SERVER['HTTP_HOST'] ?? '';
    $scriptName = $_SERVER['SCRIPT_NAME'] ?? '';
    if (!is_string($host)
        || !preg_match('/\A(?:[a-zA-Z0-9.-]+|\[[a-fA-F0-9:]+\])(?::[0-9]{1,5})?\z/', $host)
        || !is_string($scriptName)
        || strpos($scriptName, '/') !== 0
        || strpos($scriptName, '?') !== false
        || strpos($scriptName, '#') !== false) {
        return null;
    }

    $scheme = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' ? 'https' : 'http';
    return $scheme . '://' . $host . $scriptName . '?share=' . rawurlencode($token);
}

function parseDate(string $value): ?DateTimeImmutable
{
    $date = DateTimeImmutable::createFromFormat('!Y-m-d', $value);
    $errors = DateTimeImmutable::getLastErrors();

    if ($date === false
        || ($errors !== false && ($errors['warning_count'] > 0 || $errors['error_count'] > 0))
        || $date->format('Y-m-d') !== $value) {
        return null;
    }

    return $date;
}

function openLock()
{
    $handle = fopen(LOCK_FILE, 'c');
    if ($handle === false) {
        throw new RuntimeException('Impossible d’accéder au fichier de verrouillage.');
    }

    return $handle;
}

function readEntries(): array
{
    $lock = openLock();
    try {
        if (!flock($lock, LOCK_SH)) {
            throw new RuntimeException('Impossible de verrouiller le journal en lecture.');
        }

        if (!is_file(JOURNAL_FILE)) {
            return [];
        }

        $contents = file_get_contents(JOURNAL_FILE);
        if ($contents === false) {
            throw new RuntimeException('Impossible de lire le journal.');
        }

        $entries = json_decode($contents, true);
        if (!is_array($entries)) {
            throw new RuntimeException('Le fichier du journal est invalide.');
        }

        foreach ($entries as $date => $entry) {
            if (!is_array($entry)) {
                continue;
            }
            if (!isset($entry['evening_meal']) && isset($entry['dinner']) && is_string($entry['dinner'])) {
                $entries[$date]['evening_meal'] = $entry['dinner'];
            }
        }

        return $entries;
    } finally {
        flock($lock, LOCK_UN);
        fclose($lock);
    }
}

function saveEntries(array $updates): void
{
    $lock = openLock();
    try {
        if (!flock($lock, LOCK_EX)) {
            throw new RuntimeException('Impossible de verrouiller le journal en écriture.');
        }

        $entries = [];
        if (is_file(JOURNAL_FILE)) {
            $contents = file_get_contents(JOURNAL_FILE);
            if ($contents === false) {
                throw new RuntimeException('Impossible de lire le journal.');
            }

            $entries = json_decode($contents, true);
            if (!is_array($entries)) {
                throw new RuntimeException('Le fichier du journal est invalide.');
            }
        }

        foreach ($updates as $date => $entry) {
            $previousEntry = isset($entries[$date]) && is_array($entries[$date])
                ? $entries[$date]
                : [];
            if (!array_key_exists('evening_meal', $entry)
                && isset($previousEntry['dinner'])
                && is_string($previousEntry['dinner'])) {
                $entry['evening_meal'] = $previousEntry['dinner'];
            }

            foreach (['snacks'] as $archivedField) {
                if (!array_key_exists($archivedField, $entry)
                    && isset($previousEntry[$archivedField])
                    && is_string($previousEntry[$archivedField])) {
                    $entry[$archivedField] = $previousEntry[$archivedField];
                }
            }

            $entries[$date] = $entry;
        }

        $json = json_encode($entries, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
        $temporaryFile = JOURNAL_FILE . '.' . bin2hex(random_bytes(8)) . '.tmp';

        if (file_put_contents($temporaryFile, $json . PHP_EOL, LOCK_EX) === false) {
            throw new RuntimeException('Impossible d’enregistrer le journal.');
        }

        @chmod($temporaryFile, 0600);
        if (!rename($temporaryFile, JOURNAL_FILE)) {
            unlink($temporaryFile);
            throw new RuntimeException('Impossible d’enregistrer le journal.');
        }
    } finally {
        flock($lock, LOCK_UN);
        fclose($lock);
    }
}

function saveEntry(string $date, array $entry): void
{
    saveEntries([$date => $entry]);
}

function redirectToWeek(string $date): void
{
    $day = parseDate($date);
    if ($day === null) {
        throw new RuntimeException('La date à afficher est invalide.');
    }

    header('Location: ?view=day&day=' . rawurlencode($date) . '&saved=1');
    exit;
}

$errorMessage = '';
$noticeMessage = '';
$authenticated = false;
$sharedView = false;
$journalReady = false;
$shareRequested = false;
$shareToken = '';
$renderView = isset($_GET['view']) && $_GET['view'] === 'render';
$reportView = isset($_GET['view']) && $_GET['view'] === 'report';
$settingsView = isset($_GET['view']) && $_GET['view'] === 'settings';
$dailyView = !isset($_GET['view']) || $_GET['view'] === 'day';
$currentReportMonth = new DateTimeImmutable('first day of this month');
$reportEndMonth = $currentReportMonth;
$reportMonthCount = 1;
$selectedDate = date('Y-m-d');
$passwordHash = null;
$authConfig = [];
$shareUrl = null;
$isAutosaveRequest = $_SERVER['REQUEST_METHOD'] === 'POST'
    && isset($_POST['action'])
    && is_string($_POST['action'])
    && $_POST['action'] === 'autosave_week';
$isCopyShareRequest = $_SERVER['REQUEST_METHOD'] === 'POST'
    && isset($_POST['action'])
    && is_string($_POST['action'])
    && $_POST['action'] === 'copy_share';
$shareLinkToken = null;

try {
    ensureStorage();
    $authConfig = getAuthConfig();
    $passwordHash = $authConfig['password_hash'] ?? null;
    $authenticated = $passwordHash !== null
        && isset($_SESSION['authenticated_hash'])
        && is_string($_SESSION['authenticated_hash'])
        && hash_equals($passwordHash, $_SESSION['authenticated_hash']);
    $shareRequested = array_key_exists('share', $_GET);
    $shareToken = $_GET['share'] ?? '';
    $shareTokenHash = $authConfig['share_token_hash'] ?? null;
    $sharedView = $shareRequested
        && is_string($shareToken)
        && preg_match('/\A[a-f0-9]{64}\z/', $shareToken)
        && is_string($shareTokenHash)
        && hash_equals($shareTokenHash, hash('sha256', $shareToken));

    if (!isset($_SESSION['csrf_token']) || !is_string($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }

    if ($shareRequested) {
        header('Cache-Control: no-store, private');
        if (!$sharedView) {
            http_response_code(403);
            throw new JournalInputException('Ce lien de partage est invalide ou a été révoqué.');
        }
        if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
            http_response_code(405);
            throw new JournalInputException('Le lien de partage donne uniquement accès à la consultation.');
        }
        $renderView = true;
        $reportView = false;
        $settingsView = false;
        $dailyView = false;
    }

    if ($authenticated || $sharedView) {
        if ($reportView) {
            $monthValue = $_GET['month'] ?? $currentReportMonth->format('Y-m');
            $requestedReportMonth = is_string($monthValue)
                && preg_match('/\A[0-9]{4}-(?:0[1-9]|1[0-2])\z/', $monthValue)
                ? DateTimeImmutable::createFromFormat('!Y-m', $monthValue)
                : false;
            $monthErrors = DateTimeImmutable::getLastErrors();
            if ($requestedReportMonth === false
                || ($monthErrors !== false && ($monthErrors['warning_count'] > 0 || $monthErrors['error_count'] > 0))
                || $requestedReportMonth->format('Y-m') !== $monthValue) {
                http_response_code(400);
                throw new JournalInputException('Le mois du rapport demandé est invalide.');
            }
            $reportEndMonth = $requestedReportMonth;
            $monthCountValue = $_GET['months'] ?? '1';
            if (!is_string($monthCountValue) || !in_array($monthCountValue, ['1', '2', '3', '4'], true)) {
                http_response_code(400);
                throw new JournalInputException('La période du rapport demandée est invalide.');
            }
            $reportMonthCount = (int) $monthCountValue;
        }

        $weekValue = $_SERVER['REQUEST_METHOD'] === 'POST'
            ? ($_POST['date'] ?? date('Y-m-d'))
            : ($dailyView ? ($_GET['day'] ?? date('Y-m-d')) : ($_GET['week'] ?? date('Y-m-d')));
        $requestedDay = is_string($weekValue) ? parseDate($weekValue) : null;
        $viewDay = $requestedDay ?? new DateTimeImmutable('today');
        $weekStart = $viewDay->modify('monday this week');
        $weekEnd = $weekStart->modify('+6 days');
        if ($_SERVER['REQUEST_METHOD'] !== 'POST' && $requestedDay === null) {
            http_response_code(400);
            throw new JournalInputException('La date de la semaine demandée est invalide.');
        }

        $selectedDate = $dailyView
            ? $viewDay->format('Y-m-d')
            : $weekStart->format('Y-m-d');
        $entries = readEntries();
        $journalReady = true;
        if ($_SERVER['REQUEST_METHOD'] !== 'POST' && isset($_GET['saved'])) {
            $noticeMessage = 'Votre journée a bien été enregistrée.';
        }
    }

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $token = $_POST['csrf_token'] ?? '';
        if (!is_string($token) || !hash_equals($_SESSION['csrf_token'], $token)) {
            http_response_code(400);
            throw new JournalInputException('Votre session a expiré. Rechargez la page et réessayez.');
        }

        $action = $_POST['action'] ?? '';
        if ($passwordHash === null && $action === 'setup') {
            $password = $_POST['password'] ?? '';
            $confirmation = $_POST['password_confirmation'] ?? '';
            $passwordLength = is_string($password) ? characterCount($password) : null;
            if (!is_string($password) || !is_string($confirmation)
                || $passwordLength === null || $passwordLength < 12 || strlen($password) > 1024) {
                throw new JournalInputException('Choisissez un mot de passe d’au moins 12 caractères (1 024 octets maximum).');
            }
            if (!hash_equals($password, $confirmation)) {
                throw new JournalInputException('Les deux mots de passe ne correspondent pas.');
            }

            savePasswordHash(password_hash($password, PASSWORD_DEFAULT));
            $passwordHash = getPasswordHash();
            session_regenerate_id(true);
            $_SESSION['authenticated_hash'] = $passwordHash;
            header('Location: ?view=day&day=' . rawurlencode(date('Y-m-d')));
            exit;
        }

        if ($action === 'login' && $passwordHash !== null) {
            $password = $_POST['password'] ?? '';
            if (is_string($password) && password_verify($password, $passwordHash)) {
                session_regenerate_id(true);
                $_SESSION['authenticated_hash'] = $passwordHash;
                header('Location: ?view=day&day=' . rawurlencode(date('Y-m-d')));
                exit;
            }

            $errorMessage = 'Mot de passe incorrect.';
        } elseif ($action === 'create_share' && $authenticated && $passwordHash !== null) {
            $shareLinkToken = bin2hex(random_bytes(32));
            $authConfig['share_token_hash'] = hash('sha256', $shareLinkToken);
            $authConfig['share_token'] = $shareLinkToken;
            saveAuthConfig($authConfig);
            $_SESSION['share_link_flash'] = $shareLinkToken;
            header('Location: ?view=settings&share_created=1');
            exit;
        } elseif ($action === 'copy_share' && $authenticated && $passwordHash !== null) {
            $shareLinkToken = $authConfig['share_token'] ?? null;
            if (!is_string($shareLinkToken)
                || !isset($authConfig['share_token_hash'])
                || !hash_equals($authConfig['share_token_hash'], hash('sha256', $shareLinkToken))) {
                http_response_code(409);
                header('Content-Type: application/json; charset=utf-8');
                echo json_encode([
                    'copied' => false,
                    'error' => 'Le lien actif ne peut pas être récupéré. Créez un nouveau lien depuis Configuration pour pouvoir le copier ensuite sans le remplacer.',
                ], JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
                exit;
            }
            $shareUrl = createShareUrl($shareLinkToken);
            if ($shareUrl === null) {
                http_response_code(500);
                header('Content-Type: application/json; charset=utf-8');
                echo json_encode(['copied' => false, 'error' => 'Impossible de générer l’adresse du lien de partage pour ce site.'], JSON_THROW_ON_ERROR);
                exit;
            }
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode(['copied' => true, 'url' => $shareUrl], JSON_THROW_ON_ERROR);
            exit;
        } elseif ($action === 'revoke_share' && $authenticated && $passwordHash !== null) {
            unset($authConfig['share_token_hash'], $authConfig['share_token'], $_SESSION['share_link_flash']);
            saveAuthConfig($authConfig);
            header('Location: ?view=settings&share_revoked=1');
            exit;
        } elseif (($action === 'save_week' || $action === 'autosave_week')
            && $authenticated
            && $passwordHash !== null
            && isset($_SESSION['authenticated_hash'])
            && is_string($_SESSION['authenticated_hash'])
            && hash_equals($passwordHash, $_SESSION['authenticated_hash'])) {
            $weekValue = $_POST['week_start'] ?? '';
            $weekStartDate = is_string($weekValue) ? parseDate($weekValue) : null;
            $weekEntries = $_POST['entries'] ?? null;
            if ($weekStartDate === null
                || $weekStartDate->format('N') !== '1'
                || !is_array($weekEntries)
                || count($weekEntries) !== 7) {
                http_response_code(400);
                throw new JournalInputException('La semaine à enregistrer est invalide. Rechargez la page et réessayez.');
            }

            $mealNames = [
                'breakfast' => 'Petit-déjeuner',
                'snack_morning' => 'Collation du matin',
                'lunch' => 'Déjeuner',
                'snack_afternoon' => 'Collation de l’après-midi',
                'evening_meal' => 'Repas du soir',
                'snack_evening' => 'Collation du soir',
                'notes' => 'Note',
            ];
            $weekUpdates = [];
            for ($offset = 0; $offset < 7; $offset++) {
                $expectedDate = $weekStartDate->modify('+' . $offset . ' days')->format('Y-m-d');
                if (!isset($weekEntries[$expectedDate]) || !is_array($weekEntries[$expectedDate])) {
                    http_response_code(400);
                    throw new JournalInputException('Une journée de la semaine est manquante ou invalide. Rechargez la page et réessayez.');
                }

                $submittedDay = $weekEntries[$expectedDate];
                if (count($submittedDay) !== count($mealNames)
                    || array_diff(array_keys($submittedDay), array_keys($mealNames)) !== []
                    || array_diff(array_keys($mealNames), array_keys($submittedDay)) !== []) {
                    http_response_code(400);
                    throw new JournalInputException('Les champs d’une journée sont incomplets ou invalides. Rechargez la page et réessayez.');
                }

                $entry = [];
                foreach ($mealNames as $key => $label) {
                    $value = $submittedDay[$key];
                    if (!is_string($value) || strlen($value) > 20000) {
                        http_response_code(400);
                        throw new JournalInputException('Le champ « ' . $label . ' » du ' . $expectedDate . ' est trop long ou invalide.');
                    }
                    if (!isPlainJournalText($value)) {
                        http_response_code(400);
                        throw new JournalInputException('Le champ « ' . $label . ' » du ' . $expectedDate . ' contient des caractères non autorisés.');
                    }
                    $entry[$key] = trim($value);
                }
                $weekUpdates[$expectedDate] = $entry;
            }

            saveEntries($weekUpdates);
            if ($action === 'autosave_week') {
                header('Content-Type: application/json; charset=utf-8');
                echo json_encode(['saved' => true], JSON_THROW_ON_ERROR);
                exit;
            }
            header('Location: ?week=' . rawurlencode($weekStartDate->format('Y-m-d')) . '&saved=1');
            exit;
        } elseif ($action === 'logout') {
            $_SESSION = [];
            session_regenerate_id(true);
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
            header('Location: ?');
            exit;
        } elseif ($action === 'save' && $passwordHash !== null
            && isset($_SESSION['authenticated_hash'])
            && is_string($_SESSION['authenticated_hash'])
            && hash_equals($passwordHash, $_SESSION['authenticated_hash'])) {
            $dateValue = $_POST['date'] ?? '';
            if (!is_string($dateValue) || parseDate($dateValue) === null) {
                http_response_code(400);
                throw new JournalInputException('La date de cette journée est invalide.');
            }

            $mealNames = [
                'breakfast' => 'Petit-déjeuner',
                'snack_morning' => 'Collation du matin',
                'lunch' => 'Déjeuner',
                'snack_afternoon' => 'Collation de l’après-midi',
                'evening_meal' => 'Repas du soir',
                'snack_evening' => 'Collation du soir',
                'notes' => 'Note',
            ];
            $entry = [];
            foreach ($mealNames as $key => $label) {
                $value = $_POST[$key] ?? '';
                if (!is_string($value) || strlen($value) > 20000) {
                    http_response_code(400);
                    throw new JournalInputException('Le champ « ' . $label . ' » est trop long ou invalide.');
                }
                if (!isPlainJournalText($value)) {
                    http_response_code(400);
                    throw new JournalInputException('Le champ « ' . $label . ' » accepte uniquement du texte, des lettres, des chiffres et de la ponctuation courante, sans symboles de code ni requête SQL.');
                }
                $entry[$key] = trim($value);
            }

            if (array_key_exists('snacks', $_POST)) {
                $legacySnacks = $_POST['snacks'];
                if (!is_string($legacySnacks) || strlen($legacySnacks) > 20000) {
                    http_response_code(400);
                    throw new JournalInputException('Le champ « Anciennes collations » est trop long ou invalide.');
                }
                if (!isPlainJournalText($legacySnacks)) {
                    http_response_code(400);
                    throw new JournalInputException('Le champ « Anciennes collations » contient des caractères non autorisés.');
                }
                $entry['snacks'] = trim($legacySnacks);
            }

            saveEntry($dateValue, $entry);
            redirectToWeek($dateValue);
        } else {
            http_response_code(400);
            throw new JournalInputException('Action non reconnue. Rechargez la page et réessayez.');
        }
    }

    $authenticated = $passwordHash !== null
        && isset($_SESSION['authenticated_hash'])
        && is_string($_SESSION['authenticated_hash'])
        && hash_equals($passwordHash, $_SESSION['authenticated_hash']);

    if ($authenticated && $_SERVER['REQUEST_METHOD'] === 'GET') {
        if (isset($_GET['share_created']) && isset($_SESSION['share_link_flash'])
            && is_string($_SESSION['share_link_flash'])) {
            $shareLinkToken = $_SESSION['share_link_flash'];
            unset($_SESSION['share_link_flash']);
            $shareUrl = createShareUrl($shareLinkToken);
        }
    }

} catch (JournalInputException $exception) {
    $errorMessage = $exception->getMessage();
    if ($isAutosaveRequest || $isCopyShareRequest) {
        if (http_response_code() < 400) {
            http_response_code(400);
        }
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode([
            ($isAutosaveRequest ? 'saved' : 'copied') => false,
            'error' => $errorMessage,
        ], JSON_UNESCAPED_UNICODE);
        exit;
    }
} catch (Throwable $exception) {
    if ($errorMessage === '') {
        error_log('Journal alimentaire: ' . $exception->getMessage());
        if (http_response_code() < 400) {
            http_response_code(500);
        }
        $errorMessage = 'Une erreur est survenue. Vérifiez les droits d’écriture du dossier de stockage ou consultez les journaux PHP.';
    }
    if ($isAutosaveRequest || $isCopyShareRequest) {
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode([
            ($isAutosaveRequest ? 'saved' : 'copied') => false,
            'error' => $errorMessage,
        ], JSON_UNESCAPED_UNICODE);
        exit;
    }
}

$weekdayNames = ['lundi', 'mardi', 'mercredi', 'jeudi', 'vendredi', 'samedi', 'dimanche'];
$mealFields = [
    'breakfast' => 'Petit-déjeuner',
    'snack_morning' => 'Collation du matin',
    'lunch' => 'Déjeuner',
    'snack_afternoon' => 'Collation de l’après-midi',
    'evening_meal' => 'Repas du soir',
    'snack_evening' => 'Collation du soir',
    'notes' => 'Note',
];
$scoreWeights = DAILY_SCORE_WEIGHTS;
$csrfToken = isset($_SESSION['csrf_token']) && is_string($_SESSION['csrf_token'])
    ? $_SESSION['csrf_token']
    : '';
$shareEnabled = isset($authConfig['share_token_hash']) && is_string($authConfig['share_token_hash']);
$homeUrl = $sharedView
    ? '?share=' . rawurlencode($shareToken) . '&week=' . rawurlencode(date('Y-m-d'))
    : ($authenticated ? '?view=day&day=' . rawurlencode(date('Y-m-d')) : '?');
?>
<!doctype html>
<html lang="fr">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="theme-color" content="#f5f7f2">
    <title>Mon journal alimentaire</title>
    <style>
        :root {
            color-scheme: light;
            --ink: #26352e;
            --muted: #68766e;
            --green: #347653;
            --green-dark: #24593d;
            --paper: #ffffff;
            --canvas: #f4f6f1;
            --line: #e2e8df;
            --accent: #e8f2e8;
            --danger: #8f3535;
        }
        * { box-sizing: border-box; }
        body {
            margin: 0;
            background: var(--canvas);
            color: var(--ink);
            font: 16px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif;
        }
        button, input, textarea { font: inherit; }
        .shell { width: min(1440px, calc(100% - 36px)); margin: 0 auto; }
        header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 20px;
            padding: 28px 0 20px;
        }
        .brand { display: flex; align-items: center; gap: 13px; }
        .brand-home { display: block; flex: 0 0 46px; border-radius: 15px; }
        .brand-home:focus-visible { outline: 3px solid #a8cfac; outline-offset: 3px; }
        .header-actions { display: flex; align-items: center; gap: 8px; }
        .header-icon {
            display: inline-flex;
            width: 42px;
            height: 42px;
            align-items: center;
            justify-content: center;
            border: 1px solid var(--line);
            border-radius: 10px;
            background: var(--paper);
            color: var(--ink);
            cursor: pointer;
            text-decoration: none;
        }
        .header-icon:hover { border-color: #b7c8b7; background: var(--accent); }
        .header-icon[aria-current="page"],
        .header-icon[aria-current="page"]:hover {
            border-color: var(--green);
            background: var(--green);
            color: #fff;
        }
        .header-icon svg { width: 20px; height: 20px; }
        .header-icon:focus-visible { outline: 3px solid #a8cfac; outline-offset: 2px; }
        .header-icon:disabled { cursor: wait; opacity: .6; }
        .mobile-menu-toggle { display: none; }
        .mobile-menu-label { display: none; }
        .copy-status { margin: -8px 0 12px; color: var(--muted); font-size: .9rem; text-align: right; }
        .copy-status:empty { display: none; }
        .copy-fallback { width: 100%; min-height: 42px; margin: 0 0 12px; border: 1px solid var(--line); border-radius: 9px; padding: 8px 10px; }
        .brand-logo {
            display: block;
            width: 46px;
            height: 46px;
            flex: 0 0 46px;
            border-radius: 15px;
            background: var(--accent);
            object-fit: contain;
        }
        h1, h2, p { margin-top: 0; }
        h1 { margin-bottom: 2px; font-size: clamp(1.35rem, 3vw, 1.8rem); line-height: 1.2; }
        .tagline { margin: 0; color: var(--muted); font-size: .92rem; }
        .logout { margin: 0; }
        .button {
            display: inline-flex;
            min-height: 42px;
            align-items: center;
            justify-content: center;
            border: 1px solid var(--line);
            border-radius: 10px;
            background: var(--paper);
            color: var(--ink);
            padding: 8px 15px;
            text-decoration: none;
            cursor: pointer;
        }
        .button:hover { border-color: #b7c8b7; }
        .button.primary { border-color: var(--green); background: var(--green); color: #fff; font-weight: 650; }
        .button.primary:hover { background: var(--green-dark); }
        .button:focus-visible, input:focus-visible, textarea:focus-visible {
            outline: 3px solid #a8cfac;
            outline-offset: 2px;
        }
        main { padding-bottom: 42px; }
        .week-bar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 14px;
            margin: 8px 0 18px;
        }
        .journal-toolbar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 24px;
            margin: 8px 0 18px;
        }
        .journal-toolbar-main { min-width: 0; }
        .journal-toolbar-title { margin: 0 0 8px; font-size: 1rem; font-weight: 700; }
        .journal-toolbar .week-bar { justify-content: flex-start; gap: 8px; margin: 0; }
        .journal-toolbar .week-title { display: none; }
        .journal-toolbar-actions { display: flex; flex-wrap: wrap; justify-content: flex-end; gap: 8px; }
        .report-toolbar { margin: 8px 0 18px; }
        .report-toolbar-title { margin: 0 0 8px; font-size: 1rem; font-weight: 700; }
        .report-toolbar-nav { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
        .report-toolbar-nav .week-nav { flex-wrap: wrap; }
        .report-toolbar-actions { display: flex; flex: 0 0 auto; justify-content: flex-end; }
        .week-title { margin: 0; text-align: center; font-size: 1rem; font-weight: 650; }
        .week-nav { display: flex; align-items: center; gap: 8px; }
        .mobile-nav-label { display: none; }
        .desktop-nav-label { display: inline; }
        .alert {
            margin: 0 0 16px;
            border: 1px solid #efd0cb;
            border-radius: 10px;
            background: #fff6f4;
            color: var(--danger);
            padding: 12px 15px;
        }
        .alert.success { border-color: #cde3ce; background: #f0f8ef; color: var(--green-dark); }
        .week-grid {
            display: grid;
            grid-template-columns: minmax(0, 1fr);
            gap: 12px;
            align-items: start;
        }
        .daily-grid .day-card:not(.selected-day) { display: none; }
        .day-card {
            min-width: 0;
            overflow: hidden;
            border: 1px solid var(--line);
            border-radius: 14px;
            background: var(--paper);
            box-shadow: 0 2px 8px rgb(30 54 35 / 3%);
        }
        .day-card.today { border-color: #8fba96; box-shadow: 0 0 0 1px #8fba96; }
        .day-heading {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            padding: 12px 13px 10px;
            border-bottom: 1px solid var(--line);
            background: #fbfcfa;
        }
        .day-date { min-width: 0; }
        .day-heading h2 { margin: 0; font-size: .98rem; text-transform: capitalize; }
        .day-heading time { color: var(--muted); font-size: .83rem; }
        .day-score { display: grid; grid-template-columns: auto minmax(72px, 120px); align-items: center; gap: 9px; }
        .score-value { min-width: 49px; color: var(--green-dark); font-size: .9rem; font-weight: 750; text-align: right; }
        .score-track { display: block; height: 8px; overflow: hidden; border-radius: 999px; background: #e4eae1; }
        .score-fill { display: block; height: 100%; border-radius: inherit; background: var(--green); transition: width .15s ease; }
        .report-legend { display: flex; flex-wrap: wrap; gap: 12px 20px; margin: 0 0 16px; color: var(--muted); font-size: .9rem; }
        .report-legend-item { display: inline-flex; align-items: center; gap: 7px; }
        .report-period-controls { display: flex; flex-wrap: wrap; align-items: center; gap: 7px; margin: 0 0 16px; }
        .report-period-label { margin: 0 5px 0 0; color: var(--muted); font-size: .9rem; }
        .report-period-controls .button[aria-current="true"] { border-color: var(--green); background: var(--accent); color: var(--green-dark); font-weight: 700; }
        .report-dot { display: inline-block; width: 12px; height: 12px; flex: 0 0 12px; border-radius: 50%; background: var(--score-color); }
        .score-low { --score-color: #c7463e; }
        .score-medium { --score-color: #df8a16; }
        .score-high { --score-color: #34834f; }
        .report-swipe-hint { margin: -5px 0 12px; color: var(--muted); font-size: .85rem; }
        .report-month-step { display: none; align-items: center; justify-content: space-between; gap: 12px; margin: 0 0 12px; }
        .report-month-step .week-title { flex: 1; }
        .report-month-chevron { width: 42px; min-width: 42px; padding: 0; font-size: 1.25rem; }
        .report-month-chevron[aria-disabled="true"] { visibility: hidden; }
        @media (min-width: 701px) {
            .report-month-step { display: flex; }
            .report-swipe-hint { display: none; }
        }
        .report-calendar {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 14px;
            touch-action: pan-y;
        }
        .report-month {
            min-width: 0;
            border: 1px solid var(--line);
            border-radius: 12px;
            background: var(--paper);
            padding: 13px;
        }
        .report-month h2 { margin: 0 0 10px; font-size: 1rem; text-transform: capitalize; }
        .report-month-grid { display: grid; grid-template-columns: repeat(7, minmax(0, 1fr)); gap: 4px; text-align: center; }
        .report-weekday { color: var(--muted); font-size: .72rem; font-weight: 650; }
        .report-day {
            display: inline-flex;
            width: 30px;
            height: 30px;
            align-items: center;
            justify-content: center;
            justify-self: center;
            border-radius: 50%;
            color: var(--ink);
            font-size: .8rem;
            text-decoration: none;
        }
        a.report-day { background: var(--score-color); color: #fff; font-weight: 700; }
        a.report-day:hover { outline: 2px solid var(--ink); outline-offset: 2px; }
        a.report-day:focus-visible { outline: 3px solid #26352e; outline-offset: 2px; }
        .report-day.future { color: #aab3aa; }
        .sr-only {
            position: absolute;
            width: 1px;
            height: 1px;
            overflow: hidden;
            clip: rect(0, 0, 0, 0);
            white-space: nowrap;
            clip-path: inset(50%);
        }
        .day-render {
            display: grid;
            grid-template-columns: repeat(7, minmax(0, 1fr));
            gap: 12px;
            padding: 14px;
        }
        .render-meal { min-width: 0; margin: 0; }
        .render-meal:last-child { margin-bottom: 0; }
        .render-meal h3 { margin: 0 0 4px; color: #46554b; font-size: .82rem; }
        .render-meal p { margin: 0; overflow-wrap: anywhere; white-space: normal; }
        .empty-day { margin: 0; color: var(--muted); font-size: .9rem; }
        .day-form {
            display: grid;
            grid-template-columns: repeat(7, minmax(0, 1fr));
            gap: 12px;
            padding: 12px;
        }
        .view-switch { display: flex; flex-wrap: wrap; justify-content: flex-end; gap: 8px; margin: -4px 0 16px; }
        .week-save-bar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            margin: 0 0 14px;
            border: 1px solid var(--line);
            border-radius: 12px;
            background: var(--paper);
            padding: 10px 13px;
        }
        .save-status { margin: 0 0 12px; color: var(--muted); font-size: .9rem; }
        .save-status:empty { display: none; }
        .share-panel {
            margin: 8px 0 20px;
            border: 1px solid var(--line);
            border-radius: 14px;
            background: var(--paper);
            padding: 18px;
        }
        .share-panel h2 { margin: 0 0 5px; font-size: 1.05rem; }
        .share-panel p { margin: 0 0 12px; color: var(--muted); }
        .settings-main { max-width: 760px; margin: 22px auto; }
        .settings-intro { margin: 0 0 14px; color: var(--muted); }
        .share-actions { display: flex; flex-wrap: wrap; align-items: center; gap: 9px; }
        .share-url { width: min(100%, 700px); min-height: 42px; border: 1px solid var(--line); border-radius: 9px; padding: 8px 10px; }
        .share-warning { color: var(--danger) !important; font-size: .9rem; }
        .share-view-notice { margin-bottom: 16px; border: 1px solid #cde3ce; border-radius: 10px; background: #f0f8ef; color: var(--green-dark); padding: 12px 15px; }
        @media print {
            body { background: #fff; }
            .shell { width: 100%; }
            header { padding-top: 0; }
            .logout, .week-nav, .view-switch { display: none !important; }
            .week-bar { justify-content: center; }
            .week-grid { grid-template-columns: minmax(0, 1fr); gap: 8px; }
            .day-card { break-inside: avoid; box-shadow: none; }
        }
        .day-form .field { min-width: 0; margin: 0; }
        .day-form > .button { grid-column: 1 / -1; }
        .render-meal h3, .day-form label { overflow-wrap: anywhere; }
        .field { margin-bottom: 12px; }
        label { display: block; margin-bottom: 5px; color: #46554b; font-size: .8rem; font-weight: 650; }
        textarea {
            display: block;
            width: 100%;
            min-height: 76px;
            resize: vertical;
            border: 1px solid var(--line);
            border-radius: 8px;
            background: #fff;
            color: var(--ink);
            padding: 8px;
            font-size: .87rem;
            line-height: 1.4;
        }
        .field.notes textarea { min-height: 58px; }
        .day-form .button { width: 100%; min-height: 39px; padding: 7px 10px; font-size: .9rem; }
        .auth-card {
            width: min(460px, 100%);
            margin: 7vh auto;
            border: 1px solid var(--line);
            border-radius: 18px;
            background: var(--paper);
            padding: clamp(22px, 5vw, 36px);
            box-shadow: 0 8px 28px rgb(30 54 35 / 6%);
        }
        .auth-card h2 { margin-bottom: 8px; }
        .auth-card p { color: var(--muted); }
        .auth-card .field { margin: 18px 0; }
        .auth-card input {
            width: 100%;
            border: 1px solid var(--line);
            border-radius: 9px;
            padding: 11px;
        }
        .auth-card .button { width: 100%; }
        .privacy-note { margin: 22px 0 0; color: var(--muted); font-size: .83rem; }
        @media (max-width: 1100px) and (min-width: 701px) {
            .day-form, .day-render { grid-template-columns: repeat(4, minmax(0, 1fr)); }
            .report-calendar { grid-template-columns: repeat(3, minmax(0, 1fr)); }
        }
        @media (max-width: 700px) {
            .shell { width: min(100% - 24px, 520px); }
            header { position: relative; padding-top: 20px; }
            .brand h1 { display: none; }
            .mobile-menu-toggle {
                display: inline-flex;
                width: 42px;
                height: 42px;
                align-items: center;
                justify-content: center;
                border: 1px solid var(--line);
                border-radius: 10px;
                background: var(--paper);
                color: var(--ink);
                cursor: pointer;
            }
            .mobile-menu-toggle svg { width: 22px; height: 22px; }
            .mobile-menu-toggle:focus-visible { outline: 3px solid #a8cfac; outline-offset: 2px; }
            .header-actions { display: none; position: absolute; z-index: 10; top: calc(100% - 12px); right: 0; min-width: 210px; flex-direction: column; align-items: stretch; gap: 4px; padding: 8px; border: 1px solid var(--line); border-radius: 12px; background: var(--paper); box-shadow: 0 8px 24px rgb(30 54 35 / 14%); }
            .header-actions.is-open { display: flex; }
            .header-icon { width: 100%; height: auto; min-height: 42px; justify-content: flex-start; gap: 10px; padding: 8px 10px; border-color: transparent; background: transparent; }
            .header-icon svg { display: none; }
            .mobile-menu-label { display: inline; }
            .header-icon[aria-current="page"], .header-icon[aria-current="page"]:hover { border-color: var(--green); }
            .header-actions .logout .button { width: 100%; justify-content: flex-start; padding: 8px 10px; font-size: .95rem; }
            .week-grid { grid-template-columns: minmax(0, 1fr); gap: 9px; }
            .day-form, .day-render { grid-template-columns: minmax(0, 1fr); }
            .report-calendar { grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 9px; }
            .week-bar { gap: 7px; }
            .journal-toolbar { display: grid; grid-template-columns: minmax(0, 1fr) auto; align-items: center; gap: 8px 6px; }
            .journal-toolbar-main { display: contents; }
            .journal-toolbar-title { grid-column: 1 / -1; margin-bottom: 0; }
            .journal-toolbar .week-bar { grid-column: 1; min-width: 0; }
            .journal-toolbar .week-nav { gap: 4px; }
            .journal-toolbar .week-nav .button { padding: 6px 7px; font-size: .82rem; }
            .journal-toolbar-actions { grid-column: 2; grid-row: 2; justify-content: flex-end; }
            .journal-toolbar-actions .button { padding: 6px 8px; font-size: .82rem; white-space: nowrap; }
            .report-toolbar-nav { align-items: center; gap: 6px; }
            .report-toolbar-nav .week-nav { gap: 4px; }
            .report-toolbar-nav .week-nav .button,
            .report-toolbar-actions .button { padding: 6px 7px; font-size: .8rem; white-space: nowrap; }
            .week-title { font-size: .88rem; }
            .mobile-nav-label { display: inline; }
            .desktop-nav-label { display: none; }
        }
        @media (max-width: 390px) {
            .tagline { font-size: .8rem; }
            .logout .button { padding: 7px 10px; }
            .report-calendar { grid-template-columns: minmax(0, 1fr); }
        }
    </style>
</head>
<body>
<div class="shell">
    <header>
        <div class="brand">
            <a class="brand-home" href="<?= h($homeUrl) ?>" aria-label="Accueil">
                <img class="brand-logo" src="JournalAlimentaire.png" alt="">
            </a>
            <div>
                <h1>Mon journal alimentaire</h1>
            </div>
        </div>
        <?php if ($authenticated && !$sharedView): ?>
            <div class="header-actions" id="header-actions">
                <a class="header-icon" href="<?= h($homeUrl) ?>" aria-label="Journal" title="Journal"<?= !$reportView && !$settingsView ? ' aria-current="page"' : '' ?>>
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                        <path d="M5 3.5h12a2 2 0 0 1 2 2v15H7a3 3 0 0 1-3-3v-12a2 2 0 0 1 2-2z"/>
                        <path d="M4 17.5a3 3 0 0 1 3-3h12M8 7h7M8 10h7"/>
                    </svg>
                    <span class="mobile-menu-label">Journal</span>
                </a>
                <a class="header-icon" href="?view=report&amp;month=<?= h($currentReportMonth->format('Y-m')) ?>" aria-label="Rapport" title="Rapport"<?= $reportView ? ' aria-current="page"' : '' ?>>
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                        <rect x="3" y="4" width="18" height="17" rx="2"/>
                        <path d="M8 2v4M16 2v4M3 9h18M7 17v-3M12 17v-5M17 17v-2"/>
                    </svg>
                    <span class="mobile-menu-label">Rapport</span>
                </a>
                <button class="header-icon" type="button" id="copy-share-link"
                    data-csrf-token="<?= h($csrfToken) ?>"
                    aria-label="Copier le lien de lecture seule"
                    title="Copier le lien de lecture seule"
                    aria-describedby="copy-status">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                        <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/>
                        <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.72-1.71"/>
                    </svg>
                    <span class="mobile-menu-label">Lien</span>
                </button>
                <a class="header-icon" href="?view=settings" aria-label="Configuration" title="Configuration"<?= $settingsView ? ' aria-current="page"' : '' ?>>
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                        <circle cx="12" cy="12" r="3"/>
                        <path d="M19.4 15a1.7 1.7 0 0 0 .34 1.88l.06.06-1.7 2.94-.08-.02a1.7 1.7 0 0 0-1.75.6l-.05.07h-3.4l-.04-.08a1.7 1.7 0 0 0-1.75-.6l-.08.03-2.94-1.7.02-.08a1.7 1.7 0 0 0-.6-1.75l-.07-.05v-3.4l.08-.04a1.7 1.7 0 0 0 .6-1.75l-.03-.08 1.7-2.94.08.02a1.7 1.7 0 0 0 1.75-.6l.05-.07h3.4l.04.08a1.7 1.7 0 0 0 1.75.6l.08-.03 2.94 1.7-.02.08a1.7 1.7 0 0 0 .6 1.75l.07.05v3.4l-.08.04z"/>
                    </svg>
                    <span class="mobile-menu-label">Configuration</span>
                </a>
                <form class="logout" method="post">
                    <input type="hidden" name="csrf_token" value="<?= h($csrfToken) ?>">
                    <input type="hidden" name="action" value="logout">
                    <button class="button" type="submit">Se déconnecter</button>
                </form>
            </div>
            <button class="mobile-menu-toggle" type="button" aria-label="Ouvrir le menu" aria-expanded="false" aria-controls="header-actions">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true">
                    <path d="M4 6h16M4 12h16M4 18h16"/>
                </svg>
            </button>
        <?php endif; ?>
    </header>

    <main>
        <?php if ($authenticated && !$sharedView): ?>
            <p class="copy-status" id="copy-status" role="status" aria-live="polite"></p>
            <input class="copy-fallback" id="copy-fallback" type="url" aria-label="Lien de lecture seule à copier manuellement" hidden readonly>
        <?php endif; ?>
        <?php if ($errorMessage !== ''): ?>
            <div class="alert" role="alert"><?= h($errorMessage) ?></div>
        <?php endif; ?>

        <?php if ($shareRequested && !$sharedView): ?>
            <p>Demandez à la personne qui vous a transmis le lien de vérifier qu’il est toujours actif.</p>
        <?php elseif ($passwordHash === null): ?>
            <section class="auth-card">
                <h2>Créer votre mot de passe</h2>
                <p>Choisissez un mot de passe d’au moins 12 caractères. Il protégera l’accès à votre journal.</p>
                <form method="post">
                    <input type="hidden" name="csrf_token" value="<?= h($csrfToken) ?>">
                    <input type="hidden" name="action" value="setup">
                    <div class="field">
                        <label for="password">Mot de passe</label>
                        <input id="password" name="password" type="password" minlength="12" autocomplete="new-password" required>
                    </div>
                    <div class="field">
                        <label for="password_confirmation">Confirmer le mot de passe</label>
                        <input id="password_confirmation" name="password_confirmation" type="password" minlength="12" autocomplete="new-password" required>
                    </div>
                    <button class="button primary" type="submit">Créer le mot de passe</button>
                </form>
                <p class="privacy-note">Les données sont enregistrées dans des fichiers sur votre hébergement, sans base de données.</p>
            </section>
        <?php elseif (!$authenticated && !$sharedView): ?>
            <section class="auth-card">
                <h2>Votre journal est protégé</h2>
                <p>Saisissez votre mot de passe pour continuer.</p>
                <form method="post">
                    <input type="hidden" name="csrf_token" value="<?= h($csrfToken) ?>">
                    <input type="hidden" name="action" value="login">
                    <div class="field">
                        <label for="password">Mot de passe</label>
                        <input id="password" name="password" type="password" autocomplete="current-password" required autofocus>
                    </div>
                    <button class="button primary" type="submit">Ouvrir mon journal</button>
                </form>
            </section>
        <?php else: ?>
            <?php if (!$journalReady): ?>
                <p>Le journal ne peut pas être affiché pour le moment.</p>
            <?php else: ?>
            <?php if ($sharedView): ?>
                <div class="share-view-notice" role="status">Consultation en lecture seule : ce lien ne permet pas de modifier le journal.</div>
            <?php endif; ?>
            <?php if ($noticeMessage !== ''): ?>
                <div class="alert success" role="status"><?= h($noticeMessage) ?></div>
            <?php endif; ?>
            <?php
                $previousWeek = $weekStart->modify('-7 days')->format('Y-m-d');
                $nextWeek = $weekStart->modify('+7 days')->format('Y-m-d');
                $previousDay = parseDate($selectedDate)->modify('-1 day')->format('Y-m-d');
                $nextDay = parseDate($selectedDate)->modify('+1 day')->format('Y-m-d');
                $today = date('Y-m-d');
                $weekPrefix = $sharedView ? '?share=' . rawurlencode($shareToken) . '&amp;week=' : '?week=';
            ?>
            <?php if ($settingsView): ?>
                <nav class="week-bar" aria-label="Navigation de configuration">
                    <div class="week-nav">
                        <a class="button" href="?view=day&amp;day=<?= h($today) ?>">← Retour au journal</a>
                    </div>
                    <p class="week-title">Configuration</p>
                    <span aria-hidden="true"></span>
                </nav>
            <?php elseif ($reportView): ?>
                <?php
                    $reportStartMonth = $reportEndMonth->modify('-' . ($reportMonthCount - 1) . ' months');
                    $previousReportEnd = $reportEndMonth->modify('-1 month');
                    $nextReportEnd = $reportEndMonth->modify('+1 month');
                    if ($nextReportEnd > $currentReportMonth) {
                        $nextReportEnd = $currentReportMonth;
                    }
                    $monthNames = [
                        'janvier', 'février', 'mars', 'avril', 'mai', 'juin',
                        'juillet', 'août', 'septembre', 'octobre', 'novembre', 'décembre',
                    ];
                    $reportStartLabel = $monthNames[(int) $reportStartMonth->format('n') - 1] . ' ' . $reportStartMonth->format('Y');
                    $reportEndLabel = $monthNames[(int) $reportEndMonth->format('n') - 1] . ' ' . $reportEndMonth->format('Y');
                ?>
                <section class="report-toolbar" aria-label="Navigation du rapport">
                    <p class="report-toolbar-title">Rapport : <?= h($reportStartLabel) ?><?= $reportMonthCount > 1 ? ' – ' . h($reportEndLabel) : '' ?></p>
                    <nav class="report-toolbar-nav" aria-label="Navigation entre les périodes du rapport">
                        <div class="week-nav">
                            <a class="button" href="?view=report&amp;month=<?= h($previousReportEnd->format('Y-m')) ?>&amp;months=<?= $reportMonthCount ?>" aria-label="Mois précédent" title="Mois précédent">←<span class="desktop-nav-label"> Mois précédent</span></a>
                            <?php if ($reportEndMonth < $currentReportMonth): ?>
                                <a class="button" href="?view=report&amp;month=<?= h($currentReportMonth->format('Y-m')) ?>&amp;months=<?= $reportMonthCount ?>">Période récente</a>
                                <a class="button" href="?view=report&amp;month=<?= h($nextReportEnd->format('Y-m')) ?>&amp;months=<?= $reportMonthCount ?>" aria-label="Mois suivant" title="Mois suivant"><span class="desktop-nav-label">Mois suivant </span>→</a>
                            <?php endif; ?>
                        </div>
                        <div class="report-toolbar-actions">
                            <a class="button" href="?week=<?= h($weekStart->format('Y-m-d')) ?>&amp;view=render" aria-label="Vue hebdomadaire en lecture seule">Vue hebdomadaire</a>
                        </div>
                    </nav>
                </section>
            <?php else: ?>
                <section class="journal-toolbar" aria-label="Navigation du journal">
                    <div class="journal-toolbar-main">
                        <?php if ($dailyView): ?>
                            <p class="journal-toolbar-title"><?= h($weekdayNames[(int) parseDate($selectedDate)->format('N') - 1]) ?> <?= h(parseDate($selectedDate)->format('d/m/Y')) ?></p>
                            <nav class="week-bar" aria-label="Navigation entre les journées">
                                <div class="week-nav">
                                    <a class="button" href="?view=day&amp;day=<?= h($previousDay) ?>" aria-label="Jour précédent">← <span class="desktop-nav-label">Précédent</span></a>
                                    <a class="button" href="?view=day&amp;day=<?= h($today) ?>">Aujourd’hui</a>
                                    <a class="button" href="?view=day&amp;day=<?= h($nextDay) ?>" aria-label="Jour suivant"><span class="desktop-nav-label">Suivant</span> →</a>
                                </div>
                            </nav>
                        <?php else: ?>
                            <p class="journal-toolbar-title">Du <?= h($weekStart->format('d/m/Y')) ?> au <?= h($weekEnd->format('d/m/Y')) ?></p>
                            <nav class="week-bar" aria-label="Navigation entre les semaines">
                                <div class="week-nav">
                                    <a class="button" href="<?= $weekPrefix . h($previousWeek) . ($sharedView ? '' : '&amp;view=' . ($renderView ? 'render' : 'week')) ?>" aria-label="Semaine précédente">← <span class="desktop-nav-label">Précédente</span></a>
                                    <a class="button" href="<?= $weekPrefix . h(date('Y-m-d')) . ($sharedView ? '' : '&amp;view=' . ($renderView ? 'render' : 'week')) ?>">Cette semaine</a>
                                    <a class="button" href="<?= $weekPrefix . h($nextWeek) . ($sharedView ? '' : '&amp;view=' . ($renderView ? 'render' : 'week')) ?>" aria-label="Semaine suivante"><span class="desktop-nav-label">Suivante</span> →</a>
                                </div>
                            </nav>
                        <?php endif; ?>
                    </div>
                    <?php if (!$sharedView): ?>
                        <nav class="journal-toolbar-actions" aria-label="Options d’affichage du journal">
                            <?php if ($renderView): ?>
                                <a class="button" href="?view=day&amp;day=<?= h($selectedDate) ?>">Modifier les repas</a>
                            <?php elseif ($dailyView): ?>
                                <a class="button" href="?week=<?= h($weekStart->format('Y-m-d')) ?>&amp;view=week">Vue hebdomadaire</a>
                            <?php elseif ($authenticated): ?>
                                <a class="button" href="?view=day&amp;day=<?= h($selectedDate) ?>">Vue journalière</a>
                            <?php endif; ?>
                        </nav>
                    <?php endif; ?>
                </section>
            <?php endif; ?>

            <?php if (!$sharedView && $reportView): ?>
                <div class="view-switch">
                        <a class="button" href="?view=day&amp;day=<?= h($today) ?>">Journal du jour</a>
                </div>
            <?php endif; ?>

            <?php if ($reportView): ?>
                <nav class="report-period-controls" aria-label="Nombre de mois comparés">
                    <span class="report-period-label">Comparer :</span>
                    <?php for ($monthCountOption = 1; $monthCountOption <= 4; $monthCountOption++): ?>
                        <a class="button" href="?view=report&amp;month=<?= h($reportEndMonth->format('Y-m')) ?>&amp;months=<?= $monthCountOption ?>"<?= $monthCountOption === $reportMonthCount ? ' aria-current="true"' : '' ?>><?= $monthCountOption ?> mois</a>
                    <?php endfor; ?>
                </nav>
            <?php endif; ?>

            <?php if ($settingsView): ?>
                <section class="settings-main">
                    <p class="settings-intro">Gérez le lien secret qui permet une consultation en lecture seule de votre journal, sans transmettre votre mot de passe.</p>
                    <section class="share-panel" aria-labelledby="share-heading">
                        <h2 id="share-heading">Accès en lecture seule</h2>
                        <p>Le lien donne accès à toutes les semaines, y compris celles ajoutées ensuite. Toute personne qui le possède peut consulter le journal.</p>
                        <?php if ($shareUrl !== null): ?>
                            <div class="field">
                                <label for="share-url">Nouveau lien de partage — copiez-le maintenant</label>
                                <input class="share-url" id="share-url" type="url" readonly value="<?= h($shareUrl) ?>" onfocus="this.select()">
                            </div>
                            <p class="share-warning">Le lien n’est affiché qu’une seule fois. Copiez-le maintenant et conservez-le en lieu sûr.</p>
                        <?php elseif (isset($_GET['share_created'])): ?>
                            <p class="share-warning" role="alert">Le lien a été créé, mais son adresse ne peut pas être générée pour cet hôte. Vérifiez l’adresse du site et créez un nouveau lien.</p>
                        <?php endif; ?>
                        <?php if (isset($_GET['share_revoked'])): ?>
                            <p class="alert success" role="status">Le lien précédent a été révoqué.</p>
                        <?php endif; ?>
                        <div class="share-actions">
                            <form method="post">
                                <input type="hidden" name="csrf_token" value="<?= h($csrfToken) ?>">
                                <input type="hidden" name="action" value="create_share">
                                <button class="button primary" type="submit"><?= $shareEnabled ? 'Créer un nouveau lien et révoquer l’ancien' : 'Créer un lien de partage' ?></button>
                            </form>
                            <?php if ($shareEnabled): ?>
                                <form method="post" onsubmit="return confirm('Révoquer le lien de lecture seule ? Les personnes qui le possèdent ne pourront plus consulter le journal.')">
                                    <input type="hidden" name="csrf_token" value="<?= h($csrfToken) ?>">
                                    <input type="hidden" name="action" value="revoke_share">
                                    <button class="button" type="submit">Révoquer le lien</button>
                                </form>
                            <?php endif; ?>
                        </div>
                        <p class="share-warning">Utilisez HTTPS avant de partager le lien. Créer un nouveau lien révoque immédiatement le précédent.</p>
                    </section>
                </section>
            <?php elseif ($reportView): ?>
                <div class="report-legend" aria-label="Légende des scores">
                    <span class="report-legend-item"><span class="report-dot score-low"></span>0–59 %</span>
                    <span class="report-legend-item"><span class="report-dot score-medium"></span>60–89 %</span>
                    <span class="report-legend-item"><span class="report-dot score-high"></span>90–100 %</span>
                </div>
                <?php
                    $monthNames = [
                        'janvier', 'février', 'mars', 'avril', 'mai', 'juin',
                        'juillet', 'août', 'septembre', 'octobre', 'novembre', 'décembre',
                    ];
                    $weekdayInitials = ['L', 'M', 'M', 'J', 'V', 'S', 'D'];
                    $previousCalendarMonth = $reportEndMonth->modify('-1 month');
                    $nextCalendarMonth = $reportEndMonth->modify('+1 month');
                ?>
                <?php if ($reportMonthCount > 1): ?>
                    <nav class="report-month-step" aria-label="Navigation mensuelle du rapport">
                        <a class="button report-month-chevron" href="?view=report&amp;month=<?= h($previousCalendarMonth->format('Y-m')) ?>&amp;months=<?= $reportMonthCount ?>" aria-label="Mois précédent" title="Mois précédent">‹</a>
                        <p class="week-title"><?= h($reportStartLabel) ?> – <?= h($reportEndLabel) ?></p>
                        <?php if ($nextCalendarMonth <= $currentReportMonth): ?>
                            <a class="button report-month-chevron" href="?view=report&amp;month=<?= h($nextCalendarMonth->format('Y-m')) ?>&amp;months=<?= $reportMonthCount ?>" aria-label="Mois suivant" title="Mois suivant">›</a>
                        <?php else: ?>
                            <span class="button report-month-chevron" aria-hidden="true"></span>
                        <?php endif; ?>
                    </nav>
                <?php endif; ?>
                <p class="report-swipe-hint">Balayez les calendriers horizontalement pour parcourir les mois.</p>
                <section class="report-calendar" aria-label="Calendrier sur <?= $reportMonthCount ?> mois" data-report-month="<?= h($reportEndMonth->format('Y-m')) ?>" data-report-month-count="<?= $reportMonthCount ?>">
                    <?php for ($monthOffset = 0; $monthOffset < $reportMonthCount; $monthOffset++): ?>
                        <?php
                            $monthStart = $reportStartMonth->modify('+' . $monthOffset . ' months');
                            $monthNumber = (int) $monthStart->format('n');
                            $monthYear = (int) $monthStart->format('Y');
                            $daysInMonth = (int) $monthStart->format('t');
                            $leadingDays = (int) $monthStart->format('N') - 1;
                        ?>
                        <article class="report-month">
                            <h2><?= h($monthNames[$monthNumber - 1]) ?> <?= $monthYear ?></h2>
                            <div class="report-month-grid">
                                <?php foreach ($weekdayInitials as $weekdayInitial): ?>
                                    <span class="report-weekday" aria-hidden="true"><?= h($weekdayInitial) ?></span>
                                <?php endforeach; ?>
                                <?php for ($blankDay = 0; $blankDay < $leadingDays; $blankDay++): ?>
                                    <span aria-hidden="true"></span>
                                <?php endfor; ?>
                                <?php for ($dayNumber = 1; $dayNumber <= $daysInMonth; $dayNumber++): ?>
                                    <?php
                                        $calendarDate = $monthStart->setDate($monthYear, $monthNumber, $dayNumber)->format('Y-m-d');
                                        $calendarEntry = isset($entries[$calendarDate]) && is_array($entries[$calendarDate])
                                            ? $entries[$calendarDate]
                                            : [];
                                        $calendarScore = calculateDailyScore($calendarEntry);
                                        $scoreClass = $calendarScore < 60
                                            ? 'score-low'
                                            : ($calendarScore < 90 ? 'score-medium' : 'score-high');
                                        $calendarLabel = $dayNumber . ' ' . $monthNames[$monthNumber - 1] . ' ' . $monthYear;
                                    ?>
                                    <?php if ($calendarDate <= $today): ?>
                                        <a class="report-day <?= $scoreClass ?>" href="?view=day&amp;day=<?= h($calendarDate) ?>" title="<?= h($calendarLabel . ' — ' . $calendarScore . ' %') ?>" aria-label="<?= h($calendarLabel . ', score ' . $calendarScore . ' %, modifier la journée') ?>"><?= $dayNumber ?></a>
                                    <?php else: ?>
                                        <span class="report-day future" aria-label="<?= h($calendarLabel) ?>"><?= $dayNumber ?></span>
                                    <?php endif; ?>
                                <?php endfor; ?>
                            </div>
                        </article>
                    <?php endfor; ?>
                </section>
            <?php else: ?>
            <?php if (!$renderView): ?>
                <p class="save-status" id="save-status" role="status" aria-live="polite"></p>
                <noscript><p class="alert">L’enregistrement automatique nécessite JavaScript. Sans JavaScript, utilisez « Enregistrer » dans chaque journée.</p></noscript>
                <input type="hidden" id="week-start-date" value="<?= h($weekStart->format('Y-m-d')) ?>">
            <?php endif; ?>

            <section class="week-grid<?= $dailyView ? ' daily-grid' : '' ?>" aria-label="<?= $dailyView ? 'Journal de la journée' : 'Journal de la semaine' ?>">
                <?php for ($offset = 0; $offset < 7; $offset++): ?>
                    <?php
                        $day = $weekStart->modify('+' . $offset . ' days');
                        $date = $day->format('Y-m-d');
                        $entry = isset($entries[$date]) && is_array($entries[$date]) ? $entries[$date] : [];
                        $dayScore = calculateDailyScore($entry);
                    ?>
                    <article class="day-card<?= $date === $today ? ' today' : '' ?><?= $dailyView && $date === $selectedDate ? ' selected-day' : '' ?>"<?= $dailyView && $date !== $selectedDate ? ' hidden' : '' ?>>
                        <div class="day-heading">
                            <div class="day-date">
                                <h2><?= h($weekdayNames[$offset]) ?></h2>
                                <time datetime="<?= h($date) ?>"><?= h($day->format('d/m/Y')) ?></time>
                            </div>
                            <div class="day-score" data-day-score aria-label="Score du jour : <?= $dayScore ?> %">
                                <span class="score-value" data-score-value><?= $dayScore ?> %</span>
                                <span class="score-track" role="progressbar" aria-label="Repas renseignés" aria-valuemin="0" aria-valuemax="100" aria-valuenow="<?= $dayScore ?>">
                                    <span class="score-fill" data-score-fill style="width: <?= $dayScore ?>%"></span>
                                </span>
                            </div>
                        </div>
                        <?php if ($renderView): ?>
                            <?php
                                $hasContent = false;
                                foreach ($mealFields as $key => $label) {
                                    if (isset($entry[$key]) && is_string($entry[$key]) && trim($entry[$key]) !== '') {
                                        $hasContent = true;
                                        break;
                                    }
                                }
                                $archivedFields = [
                                    'snacks' => 'Anciennes collations (non classées)',
                                ];
                                foreach ($archivedFields as $key => $label) {
                                    if (isset($entry[$key]) && is_string($entry[$key]) && trim($entry[$key]) !== '') {
                                        $hasContent = true;
                                        break;
                                    }
                                }
                            ?>
                            <div class="day-render">
                                <?php if (!$hasContent): ?>
                                    <p class="empty-day">Aucun repas renseigné.</p>
                                <?php else: ?>
                                    <?php foreach ($mealFields as $key => $label): ?>
                                        <?php $value = isset($entry[$key]) && is_string($entry[$key]) ? trim($entry[$key]) : ''; ?>
                                        <section class="render-meal">
                                            <h3><?= h($label) ?></h3>
                                            <p><?= $value !== '' ? nl2br(h($value)) : '—' ?></p>
                                        </section>
                                    <?php endforeach; ?>
                                    <?php foreach ($archivedFields as $key => $label): ?>
                                        <?php $value = isset($entry[$key]) && is_string($entry[$key]) ? trim($entry[$key]) : ''; ?>
                                        <?php if ($value !== ''): ?>
                                            <section class="render-meal">
                                                <h3><?= h($label) ?></h3>
                                                <p><?= nl2br(h($value)) ?></p>
                                            </section>
                                        <?php endif; ?>
                                    <?php endforeach; ?>
                                <?php endif; ?>
                            </div>
                        <?php else: ?>
                        <form class="day-form" method="post">
                            <input type="hidden" name="csrf_token" value="<?= h($csrfToken) ?>">
                            <input type="hidden" name="action" value="save">
                            <input type="hidden" name="date" value="<?= h($date) ?>">
                            <?php foreach ($mealFields as $key => $label): ?>
                                <?php $value = isset($entry[$key]) && is_string($entry[$key]) ? $entry[$key] : ''; ?>
                                <div class="field<?= $key === 'notes' ? ' notes' : '' ?>">
                                    <label for="<?= h($key . '-' . $date) ?>"><?= h($label) ?></label>
                                    <textarea id="<?= h($key . '-' . $date) ?>" name="<?= h($key) ?>" data-score-weight="<?= $scoreWeights[$key] ?>" maxlength="20000"><?= h($value) ?></textarea>
                                </div>
                            <?php endforeach; ?>
                            <button class="button primary" type="submit">Enregistrer</button>
                        </form>
                        <?php endif; ?>
                    </article>
                <?php endfor; ?>
            </section>
            <?php endif; ?>
            <?php endif; ?>
        <?php endif; ?>
    </main>
</div>
<?php if ($authenticated && !$sharedView): ?>
<script>
(() => {
    const toggle = document.querySelector('.mobile-menu-toggle');
    const menu = document.getElementById('header-actions');
    if (!toggle || !menu) {
        return;
    }

    const closeMenu = () => {
        menu.classList.remove('is-open');
        toggle.setAttribute('aria-expanded', 'false');
        toggle.setAttribute('aria-label', 'Ouvrir le menu');
    };

    toggle.addEventListener('click', () => {
        const isOpen = menu.classList.toggle('is-open');
        toggle.setAttribute('aria-expanded', String(isOpen));
        toggle.setAttribute('aria-label', isOpen ? 'Fermer le menu' : 'Ouvrir le menu');
    });

    document.addEventListener('click', event => {
        if (!menu.contains(event.target) && !toggle.contains(event.target)) {
            closeMenu();
        }
    });

    document.addEventListener('keydown', event => {
        if (event.key === 'Escape') {
            closeMenu();
            toggle.focus();
        }
    });
})();
</script>
<script>
(() => {
    const button = document.getElementById('copy-share-link');
    const status = document.getElementById('copy-status');
    const fallback = document.getElementById('copy-fallback');
    if (!button || !status || !fallback) {
        return;
    }

    button.addEventListener('click', async () => {
        button.disabled = true;
        status.textContent = 'Récupération du lien de lecture seule…';
        fallback.hidden = true;

        try {
            const data = new FormData();
            data.append('csrf_token', button.dataset.csrfToken);
            data.append('action', 'copy_share');
            const response = await fetch(window.location.pathname + window.location.search, {
                method: 'POST',
                body: data,
                credentials: 'same-origin',
                headers: {'X-Requested-With': 'XMLHttpRequest'}
            });
            const result = await response.json();
            if (!response.ok || result.copied !== true || typeof result.url !== 'string') {
                throw new Error(result.error || 'Le lien de partage n’a pas pu être créé.');
            }

            fallback.value = result.url;
            try {
                if (!navigator.clipboard || typeof navigator.clipboard.writeText !== 'function') {
                    throw new Error('Le presse-papiers n’est pas disponible.');
                }
                await navigator.clipboard.writeText(result.url);
                status.textContent = 'Lien de lecture seule copié dans le presse-papiers.';
            } catch (clipboardError) {
                fallback.hidden = false;
                fallback.focus();
                fallback.select();
                const copied = document.execCommand('copy');
                if (copied) {
                    fallback.hidden = true;
                    status.textContent = 'Lien de lecture seule copié dans le presse-papiers.';
                } else {
                    status.textContent = 'Le lien a été créé, mais la copie automatique a échoué. Copiez-le depuis le champ affiché ci-dessous.';
                }
            }
        } catch (error) {
            status.textContent = error instanceof Error
                ? error.message
                : 'Le lien de lecture seule n’a pas pu être créé.';
        } finally {
            button.disabled = false;
        }
    });
})();
</script>
<?php endif; ?>
<?php if ($authenticated && $reportView): ?>
<script>
(() => {
    const calendar = document.querySelector('.report-calendar');
    if (!calendar) {
        return;
    }

    let touchStart = null;
    calendar.addEventListener('touchstart', event => {
        const touch = event.changedTouches[0];
        touchStart = {x: touch.clientX, y: touch.clientY};
    }, {passive: true});

    calendar.addEventListener('touchend', event => {
        if (!touchStart) {
            return;
        }
        const touch = event.changedTouches[0];
        const deltaX = touch.clientX - touchStart.x;
        const deltaY = touch.clientY - touchStart.y;
        touchStart = null;
        if (Math.abs(deltaX) < 60 || Math.abs(deltaX) < Math.abs(deltaY) * 1.3) {
            return;
        }

        const [year, month] = calendar.dataset.reportMonth.split('-').map(Number);
        const targetMonth = new Date(Date.UTC(year, month - 1 + (deltaX > 0 ? -1 : 1), 1));
        const currentMonth = new Date();
        if (targetMonth.getUTCFullYear() > currentMonth.getFullYear()
            || (targetMonth.getUTCFullYear() === currentMonth.getFullYear()
                && targetMonth.getUTCMonth() > currentMonth.getMonth())) {
            return;
        }

        const monthValue = `${targetMonth.getUTCFullYear()}-${String(targetMonth.getUTCMonth() + 1).padStart(2, '0')}`;
        const targetUrl = new URL(window.location.href);
        targetUrl.searchParams.set('view', 'report');
        targetUrl.searchParams.set('month', monthValue);
        targetUrl.searchParams.set('months', calendar.dataset.reportMonthCount);
        window.location.assign(targetUrl);
    }, {passive: true});
})();
</script>
<?php endif; ?>
<?php if ($authenticated && $journalReady && !$renderView): ?>
<script>
(() => {
    const forms = Array.from(document.querySelectorAll('.day-form'));
    const status = document.getElementById('save-status');
    const saveButton = document.getElementById('save-week-button');
    const weekStart = document.getElementById('week-start-date');
    if (forms.length !== 7 || !weekStart) {
        return;
    }

    let debounceTimer = null;
    let saving = false;
    let needsSave = false;
    let unsavedChanges = false;
    let changeRevision = 0;

    function updateDayScore(form) {
        let score = 0;
        for (const field of form.querySelectorAll('textarea[data-score-weight]')) {
            if (field.value.trim() !== '') {
                score += Number(field.dataset.scoreWeight);
            }
        }

        const scoreContainer = form.closest('.day-card').querySelector('[data-day-score]');
        scoreContainer.setAttribute('aria-label', `Score du jour : ${score} %`);
        scoreContainer.querySelector('[data-score-value]').textContent = `${score} %`;
        scoreContainer.querySelector('[role="progressbar"]').setAttribute('aria-valuenow', String(score));
        scoreContainer.querySelector('[data-score-fill]').style.width = `${score}%`;
    }

    function scheduleSave() {
        changeRevision++;
        unsavedChanges = true;
        if (status) {
            status.textContent = 'Modifications en attente d’enregistrement…';
        }
        window.clearTimeout(debounceTimer);
        debounceTimer = window.setTimeout(saveWeek, 700);
    }

    async function saveWeek() {
        window.clearTimeout(debounceTimer);
        if (saving) {
            needsSave = true;
            return;
        }

        saving = true;
        needsSave = false;
        if (status) {
            status.textContent = 'Enregistrement de la semaine…';
        }
        if (saveButton) {
            saveButton.disabled = true;
        }
        const data = new FormData();
        data.append('csrf_token', forms[0].elements.csrf_token.value);
        data.append('action', 'autosave_week');
        data.append('week_start', weekStart.value);
        for (const form of forms) {
            const date = form.elements.date.value;
            for (const field of form.querySelectorAll('textarea[name]')) {
                data.append(`entries[${date}][${field.name}]`, field.value);
            }
        }
        const submittedRevision = changeRevision;

        try {
            const response = await fetch(window.location.pathname + window.location.search, {
                method: 'POST',
                body: data,
                credentials: 'same-origin',
                headers: {'X-Requested-With': 'XMLHttpRequest'}
            });
            const result = await response.json();
            if (!response.ok || result.saved !== true) {
                throw new Error(result.error || 'La semaine n’a pas pu être enregistrée.');
            }

            if (changeRevision === submittedRevision) {
                unsavedChanges = false;
                if (status) {
                    status.textContent = 'Semaine enregistrée automatiquement.';
                }
            }
        } catch (error) {
            if (status) {
                status.textContent = error instanceof Error
                    ? error.message + ' Utilisez « Enregistrer » dans une journée pour réessayer.'
                    : 'La semaine n’a pas pu être enregistrée. Utilisez « Enregistrer » dans une journée pour réessayer.';
            }
        } finally {
            saving = false;
            if (saveButton) {
                saveButton.disabled = false;
            }
            if (needsSave) {
                needsSave = false;
                scheduleSave();
            }
        }
    }

    for (const form of forms) {
        form.addEventListener('input', () => {
            updateDayScore(form);
            scheduleSave();
        });
        form.addEventListener('submit', event => {
            event.preventDefault();
            saveWeek();
        });
    }

    if (saveButton) {
        saveButton.addEventListener('click', saveWeek);
    }
    window.addEventListener('beforeunload', event => {
        if (unsavedChanges || saving) {
            event.preventDefault();
            event.returnValue = '';
        }
    });
})();
</script>
<?php endif; ?>
</body>
</html>
