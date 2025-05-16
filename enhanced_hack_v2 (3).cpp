#define _HAS_PCH 0
#include <windows.h>
#include <d3d11.h>
#include <d3dcompiler.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>
#include <memory>
#include <thread>
#include <mutex>
#include <chrono>
#include <openssl/aes.h>
#include <detours.h>
#include <imgui.h>
#include <imgui_impl_dx11.h>
#include <imgui_impl_win32.h>
#include <urlmon.h>
#include <shlobj.h>

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "d3dcompiler.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "detours.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "urlmon.lib")

#define GITHUB_REPO "https://github.com/YourUsername/Alkad2588WH/releases/latest/download/"
#define CONFIG_KEY "YourSecretKey123"

struct Vector3 {
    float x, y, z;
    Vector3 operator+(const Vector3& other) const { return {x + other.x, y + other.y, z + other.z}; }
    Vector3 operator*(float scalar) const { return {x * scalar, y * scalar, z * scalar}; }
};

struct Vector2 {
    float x, y;
};

struct BasePlayer {
    virtual Vector3 GetPosition() = 0;
    virtual Vector3 GetHeadPosition() = 0;
    virtual int GetTeam() = 0;
    virtual bool IsLocalPlayer() = 0;
    virtual float GetHealth() = 0;
};

struct Camera {
    virtual Vector3 GetPosition() = 0;
    virtual Vector3 WorldToScreen(Vector3 position) = 0;
};

struct GameObject {
    virtual Vector3 GetPosition() = 0;
    virtual const char* GetName() = 0;
};

class GameObjectManager {
public:
    virtual uintptr_t GetActiveObjects() = 0;
    virtual int GetPlayerCount() = 0;
    virtual BasePlayer* GetPlayerByIndex(int index) = 0;
    virtual Camera* GetMainCamera() = 0;
    virtual GameObject* GetObjectByIndex(int index) = 0;
    virtual int GetObjectCount() = 0;
    virtual ~GameObjectManager() = default;
};

class HackConfig {
public:
    bool g_bESP = false, g_bAimbot = false, g_bTriggerbot = false;
    float g_fAimbotDistance = 150.0f, g_fAimbotSensitivity = 1.0f;
    float g_fESPBox[3] = {1.0f, 0.0f, 0.0f};
    float g_fObjectMarker[3] = {0.0f, 1.0f, 0.0f};
    static HackConfig& GetInstance() {
        static HackConfig instance;
        return instance;
    }
    void Save() {
        std::ofstream file("config.bin", std::ios::binary);
        if (file.is_open()) {
            file.write(reinterpret_cast<char*>(this), sizeof(HackConfig));
            file.close();
        }
    }
    void Load() {
        std::ifstream file("config.bin", std::ios::binary);
        if (file.is_open()) {
            file.read(reinterpret_cast<char*>(this), sizeof(HackConfig));
            file.close();
        }
    }
private:
    HackConfig() { Load(); }
};

class D3D11Renderer {
private:
    ID3D11Device* m_pDevice = nullptr;
    ID3D11DeviceContext* m_pContext = nullptr;
    IDXGISwapChain* m_pSwapChain = nullptr;
    ID3D11RenderTargetView* m_pRenderTargetView = nullptr;
    std::unique_ptr<ID3D11VertexShader> m_pVertexShader;
    std::unique_ptr<ID3D11PixelShader> m_pPixelShader;
    std::unique_ptr<ID3D11InputLayout> m_pInputLayout;
    std::unique_ptr<ID3D11Buffer> m_pVertexBuffer;
    std::mutex m_renderMutex;

    static void Log(const std::string& msg) {
        std::lock_guard<std::mutex> lock(m_logMutex);
        std::ofstream logfile("hack_log.txt", std::ios::app);
        logfile << msg << " [" << std::chrono::system_clock::now() << "]" << std::endl;
        std::cout << msg << std::endl;
        logfile.close();
    }

    static std::mutex m_logMutex;
    struct Vertex {
        FLOAT x, y, z;
        FLOAT r, g, b, a;
    };

public:
    bool Initialize(IDXGISwapChain* pSwapChain) {
        if (!m_pDevice) {
            if (FAILED(pSwapChain->GetDevice(__uuidof(ID3D11Device), (void**)&m_pDevice))) return false;
            m_pDevice->GetImmediateContext(&m_pContext);
            m_pSwapChain = pSwapChain;

            ID3D11Texture2D* pBackBuffer = nullptr;
            if (FAILED(m_pSwapChain->GetBuffer(0, __uuidof(ID3D11Texture2D), (void**)&pBackBuffer))) return false;
            if (FAILED(m_pDevice->CreateRenderTargetView(pBackBuffer, nullptr, &m_pRenderTargetView))) {
                pBackBuffer->Release();
                return false;
            }
            pBackBuffer->Release();
        }

        const char* vertexShaderSrc = R"(
            struct VS_INPUT { float3 pos : POSITION; float4 color : COLOR; };
            struct PS_INPUT { float4 pos : SV_POSITION; float4 color : COLOR; };
            PS_INPUT main(VS_INPUT input) { PS_INPUT output; output.pos = float4(input.pos, 1.0f); output.color = input.color; return output; }
        )";
        const char* pixelShaderSrc = R"(
            struct PS_INPUT { float4 pos : SV_POSITION; float4 color : COLOR; };
            float4 main(PS_INPUT input) : SV_TARGET { return input.color; }
        )";

        ID3DBlob* pVSBlob = nullptr, *pPSBlob = nullptr;
        if (FAILED(D3DCompile(vertexShaderSrc, strlen(vertexShaderSrc), nullptr, nullptr, nullptr, "main", "vs_5_0", 0, 0, &pVSBlob, nullptr))) return false;
        if (FAILED(m_pDevice->CreateVertexShader(pVSBlob->GetBufferPointer(), pVSBlob->GetBufferSize(), nullptr, m_pVertexShader.put()))) { pVSBlob->Release(); return false; }
        if (FAILED(D3DCompile(pixelShaderSrc, strlen(pixelShaderSrc), nullptr, nullptr, nullptr, "main", "ps_5_0", 0, 0, &pPSBlob, nullptr))) { pVSBlob->Release(); return false; }
        if (FAILED(m_pDevice->CreatePixelShader(pPSBlob->GetBufferPointer(), pPSBlob->GetBufferSize(), nullptr, m_pPixelShader.put()))) { pVSBlob->Release(); pPSBlob->Release(); return false; }

        D3D11_INPUT_ELEMENT_DESC layout[] = {
            {"POSITION", 0, DXGI_FORMAT_R32G32B32_FLOAT, 0, 0, D3D11_INPUT_PER_VERTEX_DATA, 0},
            {"COLOR", 0, DXGI_FORMAT_R32G32B32A32_FLOAT, 0, 12, D3D11_INPUT_PER_VERTEX_DATA, 0}
        };
        if (FAILED(m_pDevice->CreateInputLayout(layout, 2, pVSBlob->GetBufferPointer(), pVSBlob->GetBufferSize(), m_pInputLayout.put()))) { pVSBlob->Release(); pPSBlob->Release(); return false; }
        pVSBlob->Release(); pPSBlob->Release();

        D3D11_BUFFER_DESC bd = {0};
        bd.Usage = D3D11_USAGE_DYNAMIC;
        bd.ByteWidth = sizeof(Vertex) * 16;
        bd.BindFlags = D3D11_BIND_VERTEX_BUFFER;
        bd.CPUAccessFlags = D3D11_CPU_ACCESS_WRITE;
        if (FAILED(m_pDevice->CreateBuffer(&bd, nullptr, m_pVertexBuffer.put()))) return false;

        ImGui::CreateContext();
        ImGui::StyleColorsDark();
        ImGui_ImplWin32_Init(GetForegroundWindow());
        ImGui_ImplDX11_Init(m_pDevice, m_pContext);
        Log("D3D11 and ImGui initialized successfully");
        return true;
    }

    void DrawLine(float x1, float y1, float x2, float y2, float r, float g, float b) {
        std::lock_guard<std::mutex> lock(m_renderMutex);
        D3D11_VIEWPORT viewport;
        m_pContext->RSGetViewports(1, &viewport);
        x1 = (x1 / viewport.Width) * 2.0f - 1.0f; y1 = -((y1 / viewport.Height) * 2.0f - 1.0f);
        x2 = (x2 / viewport.Width) * 2.0f - 1.0f; y2 = -((y2 / viewport.Height) * 2.0f - 1.0f);

        Vertex vertices[] = {{x1, y1, 0.0f, r, g, b, 1.0f}, {x2, y2, 0.0f, r, g, b, 1.0f}};
        D3D11_MAPPED_SUBRESOURCE ms;
        m_pContext->Map(m_pVertexBuffer.get(), 0, D3D11_MAP_WRITE_DISCARD, 0, &ms);
        memcpy(ms.pData, vertices, sizeof(vertices));
        m_pContext->Unmap(m_pVertexBuffer.get(), 0);

        UINT stride = sizeof(Vertex), offset = 0;
        m_pContext->IASetVertexBuffers(0, 1, m_pVertexBuffer.getAddressOf(), &stride, &offset);
        m_pContext->IASetInputLayout(m_pInputLayout.get());
        m_pContext->VSSetShader(m_pVertexShader.get(), nullptr, 0);
        m_pContext->PSSetShader(m_pPixelShader.get(), nullptr, 0);
        m_pContext->IASetPrimitiveTopology(D3D11_PRIMITIVE_TOPOLOGY_LINELIST);
        m_pContext->Draw(2, 0);
    }

    void DrawRect(float x1, float y1, float x2, float y2, float r, float g, float b) {
        DrawLine(x1, y1, x2, y1, r, g, b);
        DrawLine(x2, y1, x2, y2, r, g, b);
        DrawLine(x2, y2, x1, y2, r, g, b);
        DrawLine(x1, y2, x1, y1, r, g, b);
    }

    void RenderImGui() {
        std::lock_guard<std::mutex> lock(m_renderMutex);
        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        ImGui::Begin("Alkad 2588 Hack Menu", nullptr, ImGuiWindowFlags_AlwaysAutoResize);
        if (ImGui::BeginTabBar("HackTabs")) {
            if (ImGui::BeginTabItem("WallHack")) {
                ImGui::Checkbox("Enable ESP", &HackConfig::GetInstance().g_bESP);
                ImGui::ColorEdit3("Player Box Color", HackConfig::GetInstance().g_fESPBox);
                ImGui::ColorEdit3("Object Marker Color", HackConfig::GetInstance().g_fObjectMarker);
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Aimbot")) {
                ImGui::Checkbox("Enable Aimbot", &HackConfig::GetInstance().g_bAimbot);
                ImGui::SliderFloat("Max Distance", &HackConfig::GetInstance().g_fAimbotDistance, 50.0f, 300.0f, "%.0f px");
                ImGui::SliderFloat("Sensitivity", &HackConfig::GetInstance().g_fAimbotSensitivity, 0.1f, 2.0f, "%.1f");
                ImGui::Checkbox("Enable Triggerbot", &HackConfig::GetInstance().g_bTriggerbot);
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Auto Features")) {
                if (ImGui::Button("Dump Memory")) AutoDump();
                if (ImGui::Button("Check Update")) AutoUpdate();
                if (ImGui::Button("Decrypt Dump")) Decrypter::DecryptFile("memory_dump.bin", "memory_dump_decrypted.bin", CONFIG_KEY);
                ImGui::EndTabItem();
            }
            ImGui::EndTabBar();
        }
        ImGui::Text("FPS: %.1f", ImGui::GetIO().Framerate);
        HackConfig::GetInstance().Save();
        ImGui::End();

        ImGui::Render();
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
    }

    ~D3D11Renderer() {
        ImGui_ImplDX11_Shutdown();
        ImGui_ImplWin32_Shutdown();
        ImGui::DestroyContext();
    }
};

std::mutex D3D11Renderer::m_logMutex;

class MemoryDumper {
public:
    static void AutoDump() {
        HANDLE hProcess = GetCurrentProcess();
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        uintptr_t startAddr = (uintptr_t)sysInfo.lpMinimumApplicationAddress;
        uintptr_t endAddr = (uintptr_t)sysInfo.lpMaximumApplicationAddress;

        std::ofstream dumpFile("memory_dump.bin", std::ios::binary);
        if (!dumpFile.is_open()) return;

        for (uintptr_t addr = startAddr; addr < endAddr; addr += 0x1000) {
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQueryEx(hProcess, (LPCVOID)addr, &mbi, sizeof(mbi))) {
                if (mbi.State == MEM_COMMIT && (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE))) {
                    std::vector<char> buffer(mbi.RegionSize);
                    SIZE_T bytesRead;
                    if (ReadProcessMemory(hProcess, (LPCVOID)addr, buffer.data(), mbi.RegionSize, &bytesRead)) {
                        dumpFile.write(buffer.data(), bytesRead);
                    }
                }
            }
        }
        dumpFile.close();
        D3D11Renderer::Log("Memory dump completed to memory_dump.bin");
    }
};

class AutoUpdater {
public:
    static void AutoUpdate() {
        std::wstring url = std::wstring(GITHUB_REPO) + L"enhanced_hack_v2.dll";
        std::wstring filePath;
        wchar_t appData[MAX_PATH];
        if (SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, appData) == S_OK) {
            filePath = std::wstring(appData) + L"\\AlkadHack\\enhanced_hack_v2.dll";
            CreateDirectoryW((filePath.substr(0, filePath.find_last_of(L"\\"))).c_str(), NULL);
            HRESULT hr = URLDownloadToFileW(NULL, url.c_str(), filePath.c_str(), 0, NULL);
            if (SUCCEEDED(hr)) {
                D3D11Renderer::Log("Update downloaded to " + std::string(filePath.begin(), filePath.end()));
            } else {
                D3D11Renderer::Log("Update failed, HRESULT: " + std::to_string(hr));
            }
        }
    }
};

class Decrypter {
public:
    static bool DecryptFile(const std::string& inputFile, const std::string& outputFile, const std::string& key) {
        std::ifstream inFile(inputFile, std::ios::binary);
        if (!inFile.is_open()) return false;

        std::vector<unsigned char> inData((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
        inFile.close();

        unsigned char iv[AES_BLOCK_SIZE] = {0};
        unsigned char outData[inData.size()];
        AES_KEY aesKey;
        AES_set_encrypt_key((const unsigned char*)key.c_str(), 256, &aesKey);
        AES_cbc_encrypt(inData.data(), outData, inData.size(), &aesKey, iv, AES_DECRYPT);

        std::ofstream outFile(outputFile, std::ios::binary);
        if (outFile.is_open()) {
            outFile.write((char*)outData, inData.size());
            outFile.close();
            D3D11Renderer::Log("Decrypted " + inputFile + " to " + outputFile);
            return true;
        }
        return false;
    }
};

typedef HRESULT(WINAPI* Present_t)(IDXGISwapChain*, UINT, UINT);
Present_t oPresent = nullptr;
std::unique_ptr<D3D11Renderer> g_Renderer = nullptr;

void DrawESP(BasePlayer* localPlayer, Camera* camera, GameObjectManager* gom) {
    if (!HackConfig::GetInstance().g_bESP || !localPlayer || !camera || !gom) return;

    for (int i = 0; i < gom->GetPlayerCount(); ++i) {
        BasePlayer* player = gom->GetPlayerByIndex(i);
        if (!player || player->IsLocalPlayer() || player->GetHealth() <= 0) continue;

        Vector3 pos = player->GetPosition();
        Vector3 headPos = player->GetHeadPosition();
        Vector3 screenPos = camera->WorldToScreen(pos);
        Vector3 screenHead = camera->WorldToScreen(headPos);

        if (screenPos.z > 0 && screenHead.z > 0) {
            float height = abs(screenHead.y - screenPos.y) * 1.2f;
            float width = height * 0.6f;
            g_Renderer->DrawRect(screenPos.x - width / 2, screenHead.y, screenPos.x + width / 2, screenPos.y, 
                HackConfig::GetInstance().g_fESPBox[0], HackConfig::GetInstance().g_fESPBox[1], HackConfig::GetInstance().g_fESPBox[2]);
        }
    }

    for (int i = 0; i < gom->GetObjectCount(); ++i) {
        GameObject* obj = gom->GetObjectByIndex(i);
        if (!obj) continue;
        Vector3 pos = obj->GetPosition();
        Vector3 screenPos = camera->WorldToScreen(pos);
        if (screenPos.z > 0) {
            g_Renderer->DrawRect(screenPos.x - 6, screenPos.y - 6, screenPos.x + 6, screenPos.y + 6, 
                HackConfig::GetInstance().g_fObjectMarker[0], HackConfig::GetInstance().g_fObjectMarker[1], HackConfig::GetInstance().g_fObjectMarker[2]);
        }
    }
}

void Aimbot(BasePlayer* localPlayer, BasePlayer* target, Camera* camera) {
    if (!HackConfig::GetInstance().g_bAimbot || !localPlayer || !target || !camera) return;

    Vector3 targetHead = target->GetHeadPosition() + Vector3{0, 0.2f, 0};
    Vector3 screenPos = camera->WorldToScreen(targetHead);
    if (screenPos.z > 0) {
        Vector2 targetScreen = {screenPos.x, screenPos.y};
        float distance = sqrt(pow(targetScreen.x - GetSystemMetrics(SM_CXSCREEN) / 2, 2) + pow(targetScreen.y - GetSystemMetrics(SM_CYSCREEN) / 2, 2));
        if (distance < HackConfig::GetInstance().g_fAimbotDistance) {
            float dx = (targetScreen.x - GetSystemMetrics(SM_CXSCREEN) / 2) * HackConfig::GetInstance().g_fAimbotSensitivity * 0.1f;
            float dy = (targetScreen.y - GetSystemMetrics(SM_CYSCREEN) / 2) * HackConfig::GetInstance().g_fAimbotSensitivity * 0.1f;
            mouse_event(MOUSEEVENTF_MOVE, static_cast<DWORD>(dx), static_cast<DWORD>(dy), 0, 0);
        }
    }
}

void Triggerbot(BasePlayer* localPlayer, Camera* camera, GameObjectManager* gom) {
    if (!HackConfig::GetInstance().g_bTriggerbot || !localPlayer || !camera || !gom) return;

    for (int i = 0; i < gom->GetPlayerCount(); ++i) {
        BasePlayer* target = gom->GetPlayerByIndex(i);
        if (!target || target->IsLocalPlayer() || target->GetHealth() <= 0) continue;

        Vector3 targetPos = target->GetHeadPosition();
        Vector3 screenPos = camera->WorldToScreen(targetPos);
        if (screenPos.z > 0 && abs(screenPos.x - GetSystemMetrics(SM_CXSCREEN) / 2) < 40 && abs(screenPos.y - GetSystemMetrics(SM_CYSCREEN) / 2) < 40) {
            if (GetAsyncKeyState(VK_LBUTTON) & 0x8000) {
                mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
                Sleep(10);
                mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
            }
        }
    }
}

unsigned int AOBScan(HANDLE processHandle, const char* pattern, const char* mask, unsigned int scanSize) {
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    uintptr_t currentAddress = (uintptr_t)sysInfo.lpMinimumApplicationAddress;
    std::vector<std::pair<uintptr_t, size_t>> regions;

    while (currentAddress < (uintptr_t)sysInfo.lpMaximumApplicationAddress) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(processHandle, (LPCVOID)currentAddress, &mbi, sizeof(mbi))) {
            if (mbi.State == MEM_COMMIT && (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READWRITE))) {
                regions.push_back({currentAddress, mbi.RegionSize});
            }
            currentAddress += mbi.RegionSize;
        } else {
            currentAddress += 0x1000;
        }
    }

    for (const auto& region : regions) {
        std::vector<char> buffer(region.second);
        SIZE_T bytesRead;
        if (ReadProcessMemory(processHandle, (LPCVOID)region.first, buffer.data(), region.second, &bytesRead)) {
            for (size_t i = 0; i < bytesRead - strlen(mask); ++i) {
                bool found = true;
                for (size_t j = 0; j < strlen(mask); ++j) {
                    if (mask[j] != '?' && buffer[i + j] != pattern[j]) {
                        found = false;
                        break;
                    }
                }
                if (found) {
                    D3D11Renderer::Log("AOBScan: Match at 0x" + std::to_string(region.first + i));
                    return static_cast<unsigned int>(region.first + i);
                }
            }
        }
    }
    D3D11Renderer::Log("AOBScan: No match found");
    return 0;
}

uintptr_t AutoOffset(const char* pattern, const char* mask, int offset) {
    HANDLE processHandle = GetCurrentProcess();
    unsigned int address = AOBScan(processHandle, pattern, mask, 0x100000);
    if (address) {
        uintptr_t result = address + offset;
        D3D11Renderer::Log("AutoOffset: Found at 0x" + std::to_string(result));
        CloseHandle(processHandle);
        return result;
    }
    D3D11Renderer::Log("AutoOffset: Not found");
    CloseHandle(processHandle);
    return 0;
}

HRESULT WINAPI HookedPresent(IDXGISwapChain* pSwapChain, UINT SyncInterval, UINT Flags) {
    if (!g_Renderer) {
        g_Renderer = std::make_unique<D3D11Renderer>();
        if (!g_Renderer->Initialize(pSwapChain)) {
            D3D11Renderer::Log("Failed to initialize renderer");
            return oPresent(pSwapChain, SyncInterval, Flags);
        }
    }

    g_Renderer->m_pContext->OMSetRenderTargets(1, &g_Renderer->m_pRenderTargetView, nullptr);

    GameObjectManager* gom = nullptr;
    BasePlayer* localPlayer = nullptr;
    Camera* mainCamera = nullptr;

    static const std::vector<std::pair<const char*, const char*>> patterns = {
        {"\x48\x83\xEC\x28\x48\x8B\x05", "xxxxxxx"},
        {"\x48\x89\x5C\x24\x08\x48\x89", "xxxxxxx"}
    };
    for (const auto& p : patterns) {
        uintptr_t gomAddress = AutoOffset(p.first, p.second, 0x7);
        if (gomAddress) {
            gom = reinterpret_cast<GameObjectManager*>(gomAddress);
            break;
        }
    }

    if (gom) {
        localPlayer = gom->GetPlayerByIndex(0);
        mainCamera = gom->GetMainCamera();
        std::thread espThread(DrawESP, localPlayer, mainCamera, gom);
        std::thread aimbotThread(Aimbot, localPlayer, gom->GetPlayerByIndex(1), mainCamera);
        std::thread triggerThread(Triggerbot, localPlayer, mainCamera, gom);
        espThread.join();
        aimbotThread.join();
        triggerThread.join();
    }

    g_Renderer->RenderImGui();
    return oPresent(pSwapChain, SyncInterval, Flags);
}

void SetupHook() {
    HMODULE hDXGI = GetModuleHandleA("dxgi.dll");
    if (!hDXGI) {
        D3D11Renderer::Log("Failed to get dxgi.dll handle");
        return;
    }

    oPresent = (Present_t)GetProcAddress(hDXGI, "Present");
    if (!oPresent) {
        D3D11Renderer::Log("Failed to get Present address");
        return;
    }

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    if (DetourAttach(&(PVOID&)oPresent, HookedPresent) != NO_ERROR) {
        D3D11Renderer::Log("Failed to attach Detour to Present");
        DetourTransactionAbort();
        return;
    }
    if (DetourTransactionCommit() != NO_ERROR) {
        D3D11Renderer::Log("Failed to commit Detour transaction");
        return;
    }
    D3D11Renderer::Log("Hook on Present set successfully");
}

DWORD WINAPI MainThread(LPVOID lpParam) {
    SetupHook();
    while (true) {
        Sleep(1);
    }
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        CreateThread(NULL, 0, MainThread, NULL, 0, NULL);
    } else if (ul_reason_for_call == DLL_PROCESS_DETACH) {
        g_Renderer.reset();
        if (oPresent) {
            DetourTransactionBegin();
            DetourUpdateThread(GetCurrentThread());
            DetourDetach(&(PVOID&)oPresent, HookedPresent);
            DetourTransactionCommit();
            oPresent = nullptr;
        }
    }
    return TRUE;
}