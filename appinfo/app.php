<?php

require(dirname(__FILE__) . "/../vendor/autoload.php");
use GuzzleHttp\Client;

function setRedirectHeader(){
    $loginUrl = getenv("LOGIN_URL");
    header("Location: " . $loginUrl);
}

function fetchUserInfo(){
    $client = new GuzzleHttp\Client();
    $loginUrl = getenv("LOGIN_URL");
    $apiUrl = getenv("API_URL");
    try {
        if(!isset($_COOKIE["mikan_token"])){
            throw new Exception("No token");
        }
        $token = $_COOKIE["mikan_token"];

        $res = $client->post($apiUrl . "/auth/verify/", [ GuzzleHttp\RequestOptions::JSON => [
            "token" => $token
        ]]);

        if($res->getStatusCode() !== 200){
            throw new Exception("Invalid token");
        }
    } catch(Exception $e) {
        setrawcookie("redirect", "https://" . $_SERVER["HTTP_HOST"], 0, "/", "." . parse_url($loginUrl, PHP_URL_HOST));
        setRedirectHeader();
        exit;
    }

    setrawcookie("redirect", "", time()-1, "/", "." . parse_url($loginUrl, PHP_URL_HOST));

    $res = $client->request("GET", $apiUrl . '/account/', [
        'headers' => [
            'Authorization' => 'Bearer ' . $token
        ]
    ]);
    $body = json_decode($res->getBody());

    return [
        "is_staff" => $body->is_staff,
        "uid" => $body->uid,
        "email" => $body->email,
        "displayName" => $body->first_name . " " . $body->last_name,
    ];
}

function loginWithMikanToken(){
    $session = OC::$server->getUserSession();

    if(!$session->isLoggedIn()){
        $userInfo = fetchUserInfo();
        $userManager = OC::$server->getUserManager();
        $groupManager = OC::$server->getGroupManager();

        $user = $userManager->get($userInfo["uid"]);
        if(!$user){
            $user = $userManager->createUser($userInfo["uid"], random_bytes(256));
        }

        $user->setEMailAddress($userInfo["email"]);
        $user->setDisplayName($userInfo["displayName"]);

        $membersGroup = $groupManager->get("members");
        if(!$membersGroup){
            $membersGroup = $groupManager->createGroup("members");
        }

        if(!$membersGroup->inGroup($user)){
            $membersGroup->addUser($user);
        }

        $adminGroup = $groupManager->get("admin");
        if(!$adminGroup){
            $adminGroup = $groupManager->createGroup("admin");
        }

        if($userInfo["is_staff"] && !$adminGroup->inGroup($user)){
            $adminGroup->addUser($user);
        }

        $session->setUser($user);
        $session->setLoginName($user->getUID());

        OC::$server->getCsrfTokenManager()->refreshToken();
        OC_Util::setupFS($user->getUID());

        // first login
        if($user->updateLastLoginTimestamp()){
            $userFolder = OC::$server->getUserFolder($user->getUID());
            OC_Util::copySkeleton($user->getUID(), $userFolder);
        }

        $session->createSessionToken(OC::$server->getRequest(), $user->getUID(), $user->getUID());
    }
}

if(strpos($_SERVER["REQUEST_URI"], "/login") === 0){
    loginWithMikanToken();
}

if(strpos($_SERVER["REQUEST_URI"], "/logout") === 0){
    setcookie('mikan_token', '', time() - 1800);
}
