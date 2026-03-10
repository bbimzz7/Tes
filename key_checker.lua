-- VertictHub Key System v2.1
-- Taruh di PALING ATAS script, sebelum semua kode lain
-- ============================================================

local Players     = game:GetService("Players")
local HttpService = game:GetService("HttpService")
local LocalPlayer = Players.LocalPlayer

local API_BASE  = "https://vh-api-alpha.vercel.app" -- ganti URL Vercel kamu
local KEY_FILE  = "vh_key.txt"
local RETRY_MAX = 3
local TIMEOUT   = 10

-- ── HWID ──────────────────────────────────────────────────────
local function getHWID()
    local uid = tostring(LocalPlayer.UserId or "0")
    local mid = "fallback"

    pcall(function()
        local id = tostring(game:GetService("RbxAnalyticsService"):GetClientId())
        if id and id ~= "" and id ~= "nil" and id ~= "undefined" then
            mid = id
        end
    end)

    if mid == "fallback" then
        pcall(function()
            local info = LocalPlayer:GetJoinData()
            local sgid = tostring(info and info.SourceGameId or "")
            if sgid ~= "" and sgid ~= "nil" and sgid ~= "0" then
                mid = sgid
            end
        end)
    end

    if mid == "fallback" then
        pcall(function()
            mid = tostring(game.GameId or "0")
        end)
    end

    local hwid = uid .. "-" .. mid
    hwid = hwid:gsub("undefined", "x"):gsub("nil", "x")
    return hwid
end

-- ── Player info ───────────────────────────────────────────────
local function getPlayerInfo()
    local username = "unknown"
    local userId   = "0"
    pcall(function()
        username = tostring(LocalPlayer.Name)
        userId   = tostring(LocalPlayer.UserId)
    end)
    return username, userId
end

-- ── Key storage ───────────────────────────────────────────────
local function saveKey(key)
    pcall(function() writefile(KEY_FILE, key) end)
end

local function loadKey()
    local ok, key = pcall(function() return readfile(KEY_FILE) end)
    if ok and type(key) == "string" and #key > 5 then
        return key:match("^%s*(.-)%s*$")
    end
    return nil
end

local function clearKey()
    pcall(function() writefile(KEY_FILE, "") end)
end

-- ── HTTP GET dengan retry ─────────────────────────────────────
local function httpGet(url)
    local result, err
    for i = 1, RETRY_MAX do
        local ok, res = pcall(function()
            return game:HttpGet(url, true)
        end)
        if ok and res and #res > 0 then
            return res, nil
        end
        err = res or "Koneksi gagal"
        if i < RETRY_MAX then task.wait(1.5) end
    end
    return nil, err
end

-- ── Cek key ke API ────────────────────────────────────────────
local function checkKeyAPI(key, hwid)
    local username, userId = getPlayerInfo()

    local url = API_BASE
        .. "/api/checkkey?key="      .. HttpService:UrlEncode(key)
        .. "&hwid="                  .. HttpService:UrlEncode(hwid)
        .. "&username="              .. HttpService:UrlEncode(username)
        .. "&userId="                .. HttpService:UrlEncode(userId)

    local raw, httpErr = httpGet(url)
    if not raw then
        return false, "❌ Gagal koneksi ke server (" .. (httpErr or "?") .. ")"
    end

    local ok, data = pcall(function() return HttpService:JSONDecode(raw) end)
    if not ok or type(data) ~= "table" then
        return false, "❌ Response server tidak valid"
    end

    if data.valid then
        local exp = ""
        if data.expires then
            exp = " | Expire: " .. tostring(data.expires):sub(1, 10)
        end
        local msg = data.bound
            and ("✅ Key aktif & terhubung ke device ini" .. exp)
            or  ("✅ Key valid" .. exp)
        return true, msg
    else
        local reason = data.reason or "Key tidak valid"
        -- Clear key kalau expired atau tidak ditemukan
        if reason:find("expired") or reason:find("tidak ditemukan") then
            clearKey()
        end
        return false, "❌ " .. reason
    end
end

-- ══════════════════════════════════════════════════════════════
-- GUI
-- ══════════════════════════════════════════════════════════════

local KeyGui = Instance.new("ScreenGui")
KeyGui.Name           = "VHKeySystem"
KeyGui.ResetOnSpawn   = false
KeyGui.DisplayOrder   = 9999
KeyGui.IgnoreGuiInset = true
KeyGui.Parent         = game:GetService("CoreGui")

-- Overlay gelap
local Overlay = Instance.new("Frame", KeyGui)
Overlay.Size                   = UDim2.new(1, 0, 1, 0)
Overlay.BackgroundColor3       = Color3.fromRGB(2, 2, 8)
Overlay.BackgroundTransparency = 0.15
Overlay.BorderSizePixel        = 0
Overlay.ZIndex                 = 1

-- Card utama
local Card = Instance.new("Frame", KeyGui)
Card.Size             = UDim2.new(0, 380, 0, 300)
Card.Position         = UDim2.new(0.5, -190, 0.5, -130)
Card.BackgroundColor3 = Color3.fromRGB(9, 9, 18)
Card.BorderSizePixel  = 0
Card.ZIndex           = 2
Instance.new("UICorner", Card).CornerRadius = UDim.new(0, 16)

local Stroke = Instance.new("UIStroke", Card)
Stroke.Color     = Color3.fromRGB(70, 70, 160)
Stroke.Thickness = 1.5

local Pad = Instance.new("UIPadding", Card)
Pad.PaddingLeft   = UDim.new(0, 22)
Pad.PaddingRight  = UDim.new(0, 22)
Pad.PaddingTop    = UDim.new(0, 22)
Pad.PaddingBottom = UDim.new(0, 22)

local Layout = Instance.new("UIListLayout", Card)
Layout.Padding   = UDim.new(0, 10)
Layout.SortOrder = Enum.SortOrder.LayoutOrder

-- ── Helpers UI ────────────────────────────────────────────────
local function makeLabel(parent, text, size, color, order, bold)
    local lbl = Instance.new("TextLabel", parent)
    lbl.Size               = UDim2.new(1, 0, 0, size)
    lbl.BackgroundTransparency = 1
    lbl.Text               = text
    lbl.TextColor3         = color
    lbl.TextSize           = size
    lbl.Font               = bold and Enum.Font.SourceSansBold or Enum.Font.SourceSans
    lbl.TextXAlignment     = Enum.TextXAlignment.Center
    lbl.LayoutOrder        = order
    lbl.TextWrapped        = true
    return lbl
end

local function makeBtn(parent, text, bgColor, textColor, order)
    local btn = Instance.new("TextButton", parent)
    btn.Size             = UDim2.new(1, 0, 0, 38)
    btn.BackgroundColor3 = bgColor
    btn.BorderSizePixel  = 0
    btn.Text             = text
    btn.TextColor3       = textColor
    btn.TextSize         = 13
    btn.Font             = Enum.Font.SourceSansBold
    btn.LayoutOrder      = order
    btn.AutoButtonColor  = false
    Instance.new("UICorner", btn).CornerRadius = UDim.new(0, 10)
    return btn
end

-- ── Elemen GUI ────────────────────────────────────────────────
makeLabel(Card, "⚡ VertictHub", 22, Color3.fromRGB(150, 150, 255), 0, true)
makeLabel(Card, "Masukkan key untuk melanjutkan", 12, Color3.fromRGB(90, 90, 120), 1, false)

-- Separator
local Sep = Instance.new("Frame", Card)
Sep.Size             = UDim2.new(1, 0, 0, 1)
Sep.BackgroundColor3 = Color3.fromRGB(40, 40, 80)
Sep.BorderSizePixel  = 0
Sep.LayoutOrder      = 2

-- Input background
local InputBg = Instance.new("Frame", Card)
InputBg.Size             = UDim2.new(1, 0, 0, 40)
InputBg.BackgroundColor3 = Color3.fromRGB(14, 14, 26)
InputBg.BorderSizePixel  = 0
InputBg.LayoutOrder      = 3
Instance.new("UICorner", InputBg).CornerRadius = UDim.new(0, 10)
local InputStroke = Instance.new("UIStroke", InputBg)
InputStroke.Color = Color3.fromRGB(50, 50, 90)

local KeyInput = Instance.new("TextBox", InputBg)
KeyInput.Size               = UDim2.new(1, -20, 1, -10)
KeyInput.Position           = UDim2.new(0, 10, 0, 5)
KeyInput.BackgroundTransparency = 1
KeyInput.Text               = ""
KeyInput.PlaceholderText    = "VH-XXXXXX-XXXXXX-XXXXXX"
KeyInput.PlaceholderColor3  = Color3.fromRGB(60, 60, 100)
KeyInput.TextColor3         = Color3.fromRGB(180, 255, 200)
KeyInput.TextSize           = 14
KeyInput.Font               = Enum.Font.SourceSans
KeyInput.TextXAlignment     = Enum.TextXAlignment.Center
KeyInput.ClearTextOnFocus   = false

local SubmitBtn = makeBtn(Card,
    "✅  Verifikasi Key",
    Color3.fromRGB(55, 55, 140),
    Color3.fromRGB(210, 210, 255),
    4
)

local GetKeyBtn = makeBtn(Card,
    "🔗  Belum punya key? Ambil di sini",
    Color3.fromRGB(20, 20, 36),
    Color3.fromRGB(90, 90, 180),
    5
)

local StatusL = makeLabel(Card, "", 11, Color3.fromRGB(200, 100, 100), 6, false)
StatusL.TextWrapped = true

-- Fix ZIndex
for _, v in pairs(Card:GetDescendants()) do
    if v:IsA("TextLabel") or v:IsA("TextButton") or v:IsA("TextBox") or v:IsA("Frame") then
        v.ZIndex = 3
    end
end

-- ── Logic ─────────────────────────────────────────────────────
local isBusy = false

local function setStatus(msg, isOk)
    StatusL.Text       = msg
    StatusL.TextColor3 = isOk
        and Color3.fromRGB(80, 220, 120)
        or  Color3.fromRGB(220, 90, 90)
end

local function setBusy(state)
    isBusy           = state
    SubmitBtn.Active = not state
    SubmitBtn.BackgroundTransparency = state and 0.4 or 0
end

local function doVerify(key)
    if isBusy then return end

    -- Validasi format key di client
    if not key:match("^VH%-[A-F0-9][A-F0-9][A-F0-9][A-F0-9][A-F0-9][A-F0-9]%-[A-F0-9][A-F0-9][A-F0-9][A-F0-9][A-F0-9][A-F0-9]%-[A-F0-9][A-F0-9][A-F0-9][A-F0-9][A-F0-9][A-F0-9]$") then
        setStatus("❌ Format key salah — contoh: VH-A1B2C3-D4E5F6-789ABC", false)
        return
    end

    setBusy(true)
    setStatus("⏳ Memeriksa key...", true)

    local hwid             = getHWID()
    local valid, msg       = checkKeyAPI(key, hwid)

    setBusy(false)

    if valid then
        setStatus(msg, true)
        saveKey(key)
        task.wait(1.8)
        KeyGui:Destroy()
    else
        setStatus(msg, false)
    end
end

-- ── Events ────────────────────────────────────────────────────
SubmitBtn.MouseButton1Click:Connect(function()
    local key = KeyInput.Text:gsub("%s+", ""):upper()
    doVerify(key)
end)

SubmitBtn.MouseEnter:Connect(function()
    if not isBusy then SubmitBtn.BackgroundColor3 = Color3.fromRGB(70, 70, 170) end
end)
SubmitBtn.MouseLeave:Connect(function()
    if not isBusy then SubmitBtn.BackgroundColor3 = Color3.fromRGB(55, 55, 140) end
end)

KeyInput.FocusLost:Connect(function(enter)
    if enter then
        doVerify(KeyInput.Text:gsub("%s+", ""):upper())
    end
end)

KeyInput.Focused:Connect(function()
    InputStroke.Color = Color3.fromRGB(90, 90, 180)
end)
KeyInput.FocusLost:Connect(function()
    InputStroke.Color = Color3.fromRGB(50, 50, 90)
end)

-- ── Get key button — generate signed link ────────────────────
GetKeyBtn.MouseButton1Click:Connect(function()
    local hwid               = getHWID()
    local username, userId   = getPlayerInfo()

    setStatus("⏳ Membuat link aman...", true)

    local hwidEnc     = HttpService:UrlEncode(tostring(hwid))
    local usernameEnc = HttpService:UrlEncode(tostring(username))
    local userIdEnc   = HttpService:UrlEncode(tostring(userId))
    local tokenUrl    = API_BASE .. "/api/token?hwid=" .. hwidEnc
                        .. "&username=" .. usernameEnc
                        .. "&userId="   .. userIdEnc

    local ok, raw = pcall(function()
        return game:HttpGet(tokenUrl, true)
    end)

    if not ok or not raw then
        setStatus("❌ Gagal buat link, coba lagi", false)
        return
    end

    local parsed = pcall(function()
        local data = HttpService:JSONDecode(raw)
        local url  = API_BASE .. (data.url or "")
        -- Coba copy ke clipboard
        local clipOk = pcall(function() setclipboard(url) end)
        if clipOk then
            setStatus("✓ Link disalin! Buka di browser → klik Generate", true)
        else
            setStatus("Buka: " .. url, true)
        end
    end)

    if not parsed then
        setStatus("❌ Response tidak valid", false)
    end
end)

-- ── Auto load key tersimpan ───────────────────────────────────
task.spawn(function()
    local saved = loadKey()
    if saved and #saved > 5 then
        KeyInput.Text = saved
        setStatus("⏳ Memeriksa key tersimpan...", true)
        task.wait(0.4)
        doVerify(saved:upper())
    end
end)

-- ── Block eksekusi sampai key valid ──────────────────────────
while KeyGui and KeyGui.Parent do
    task.wait(0.1)
end

-- ============================================================
-- ✅ KEY VALID — SISA KODE SCRIPT DI BAWAH INI
-- ============================================================
