local passes, fails = 0, 0

function pass(text)
    passes += 1
    print("✅ "..text)
end

function warn_(text)
    warn("⚠️ "..text)
end

function fail(text, lol)
    fails += 1
    if not lol then
        print("⛔ "..text)
    else
        print("⛔ "..text.." ("..lol..")")
    end
end

function test(func)
    func()
end


local executorname, version = identifyexecutor()
print("\n")
print("Full Executor test")
print("✅ - Pass, ⛔ - Fail")
print("Lets see if "..executorname.." Dll is not xeno")
print("Made by Bdokkx | Join discord.gg/ronix, discord.gg/getgalaxy")
print("\n")

warn_("Loading tests... please wait")
test(function()
    task.spawn(function()
        game.CoreGui.ChildAdded:Connect(function(v)
            if v:IsA("ScreenGui") then
                if v.Name == "Window" or v.Name == "MainMenu" or v.Name == "ScreenGui" or v.Name == "Intro" then
                    v.Enabled = false
                end
            end
        end)

        while wait() do
            for _, v in pairs(game.CoreGui:GetChildren()) do
                if v:IsA("ScreenGui") then
                    if v.Name == "Window" or v.Name == "MainMenu" or v.Name == "ScreenGui" or v.Name == "Intro" then
                        v.Enabled = false
                    end
                end
            end
        end
    end)
    loadstring(game:HttpGet("https://raw.githubusercontent.com/infyiff/backup/main/dex.lua"))()

    local Timeout = 5
    local ElapsedTime = 0
    local StartTime = os.time()

    repeat
        wait(0.1)
        ElapsedTime = os.time() - StartTime
    until game.CoreGui:FindFirstChild("Window") or ElapsedTime >= Timeout

    if not game.CoreGui:FindFirstChild("Window") then
        fail("Dex was not located or took too long to load")
        return
    end

    local FoundElement = nil
    for i, v in pairs(game:GetDescendants()) do
        pcall(function()
            if v.Text == "StarterGui" then
                FoundElement = v
            end
        end)
    end

    if not FoundElement then
        fail("Dex was not able to find children of Game (Xeno Bug)", "nil instances moment 🤑")
    else
        pass("Dex loaded all objects successfully!")
    end

    warn_("Unloading Dex..")
    repeat wait() until not game.CoreGui:FindFirstChild("Intro")

    for _, v in pairs(game.CoreGui:GetChildren()) do
        if v:IsA("ScreenGui") then
            if v.Name == "Window" or v.Name == "MainMenu" or v.Name == "ScreenGui" or v.Name == "Intro" then
                v:Destroy()
            end
        end
    end
end)

test(function()
    local p, e = pcall(function()
        local scriptname = getfenv().script.name
        if scriptname ~= nil and string.len(scriptname) == 36 then
            error("Skidded")
        end
    end)

    if p then
        pass("Fake Environment script name was not generated the same way as Xeno")
    else
        fail("Fake Environment script name was generated with HttpService:GenerateGUID()")
    end
end)

test(function()
    local scriptpath = getfenv().script:GetFullName()
    if scriptpath ~= nil then
		if string.find(scriptpath, "RobloxReplicatedStorage") then
			fail("Fake Environment script is located in RobloxReplicatedStorage")
        else
            pass("Fake Environment script is not located in RobloxReplicatedStorage")
		end
    else
        pass("Fake Environment script is not located in RobloxReplicatedStorage")
    end
end)

test(function()
    if about and about.__name and about.__version and about.__publisher then
        fail("About table exists and is 1:1 to Xeno", "did "..about._publisher.." really make this 🤔")
        return
    elseif about and about.__publisher then
        fail("About table exists and is 1:1 to Xeno", "did "..about._publisher.." really make this 🤔")
        return
    elseif about then
        local name, idc = identifyexecutor()
        fail("About table exists and is 1:1 to Xeno", "did "..name.." devs really make this 🤔")
        return
    else
        pass("About table is original")
        return
    end
end)

test(function()
    local p, e = pcall(function()
        local test = game:GetService("LinkingService"):OpenUrl()
        if test == true then
            fail("LinkingService RCE not patched (Common in Xeno 1.0.4)", "vulnerable ✅✅✅")
            return
        end
    end)

    if e and string.find(e, "Attempt to call a blocked function: OpenUrl") then
        fail("Blocked function message is 1:1 to Xeno")
        return
    end

    pass("Blocked function patch is original")
end)

test(function()
    local p, e = pcall(function()
        local execname, execvers = identifyexecutor()
        local exectable = nil

        function GrabExecTable()
            local env = getgenv()
            
            for key, value in pairs(env) do
                if type(value) == "table" then
                    if value.PID then
                        return key, value
                    end
                end
            end

            pass("Default Xeno variable GUID does not exist in the environment")
            pass("Default Xeno variable PID does not exist in the environment")
            pass("Default Xeno function get_real_address does not exist in the environment")
            pass("Default Xeno function spoof_instance does not exist in the environment")
            pass("Default Xeno function GetGlobal does not exist in the environment")
            pass("Default Xeno function SetGlobal does not exist in the environment")
            pass("Default Xeno function Compile does not exist in the environment")
            pass("Default Xeno function HttpSpy does not exist in the environment")

            return nil, nil
        end
        
        local p, e = pcall(function()
            GrabExecTable()
        end)

        if p then
            local tname, ttable = GrabExecTable()
        end

        if e then
            pass("Default Xeno variable GUID does not exist in the environment")
            pass("Default Xeno variable PID does not exist in the environment")
            pass("Default Xeno function get_real_address does not exist in the environment")
            pass("Default Xeno function spoof_instance does not exist in the environment")
            pass("Default Xeno function GetGlobal does not exist in the environment")
            pass("Default Xeno function SetGlobal does not exist in the environment")
            pass("Default Xeno function Compile does not exist in the environment")
            pass("Default Xeno function HttpSpy does not exist in the environment")
        end

        if ttable ~= nil then
            local name = execname
            local exectable = ttable

            if exectable["GUID"] then
                fail("GUID variable exists in the global "..tname.." table")
            else
                pass("Default Xeno variable GUID does not exist in the environment for "..name)
            end

            if exectable["PID"] then
                fail("PID variable exists in the global "..tname.." table")
            else
                pass("Default Xeno variable PID does not exist in the environment for "..name)
            end

            if exectable["get_real_address"] then
                fail("get_real_address function exists in the global "..tname.." table")
            else
                pass("Default Xeno function get_real_address does not exist in the environment for "..name)
            end

            if exectable["spoof_instance"] then
                fail("spoof_instance function exists in the global "..tname.." table")
            else
                pass("Default Xeno function spoof_instance does not exist in the environment for "..name)
            end

            if exectable["GetGlobal"] then
                fail("GetGlobal function exists in the global "..tname.." table")
            else
                pass("Default Xeno function GetGlobal does not exist in the environment for "..name, "xeno what is the point of this")
            end

            if exectable["SetGlobal"] then
                fail("SetGlobal function exists in the global "..tname.." table")
            else
                pass("Default Xeno function SetGlobal does not exist in the environment for "..name, "xeno what is the point of this v2")
            end

            if exectable["Compile"] then
                fail("Compile function exists in the global "..tname.." table", "global compile function 😎💯")
            else
                pass("Default Xeno function Compile does not exist in the environment for "..name)
            end

            if exectable["HttpSpy"] then
                fail("HttpSpy function exists in the global "..tname.." table", "luarmorK 🤑✅")
            else
                pass("Default Xeno function HttpSpy does not exist in the environment for "..name)
            end
        end
    end)
end)

local rate = math.round(passes / (passes + fails) * 100)
local outOf = passes .. " out of " .. (passes + fails)

print("\n")

print("Skid Summary")
print("✅ Tested with a " .. rate .. "% success rate (" .. outOf .. ")")
print("⛔ " .. fails .. " tests failed")

if rate < 51 then
    local executorname, version = identifyexecutor()
    warn("⚠️ Your executor (AKA "..executorname..") is skidded, please stop using it")
end

local executorname, version = identifyexecutor()

if passes / math.max(fails, 1) < 2 then
    warn("⚠️  "..executorname.." Dll is xeno ✅ ")
else
    warn("⚠️  "..executorname.." Dll is not xeno ⛔ ")
end


print("\n")
print("Made by Bdokkx | Join discord.gg/ronix, discord.gg/getgalaxy")

wait(2)
print("\n")
print("\n")
print("\n")
print("_________________________________________________________________________________________________________________________________________")
warn("                                                 running Normal Unc test in 5 seconds")
wait(5) 

local passes, fails, undefined = 0, 0, 0
local running = 0

local function getGlobal(path)
	local value = getgenv and getgenv() or getfenv(2)

	while value ~= nil and path ~= "" do
		local name, nextValue = string.match(path, "^([^.]+)%.?(.*)$")
		value = value[name]
		path = nextValue
	end

	return value
end

local function test(name, aliases, callback, target)
	running = running + 1

	task.spawn(function()
		if not callback then
			print("⏺️ " .. name)
		elseif not getGlobal(name) then
			fails = fails + 1
			warn("⛔ " .. name)
		else
			local success, message = pcall(callback)
	        name = tostring(name)
			message = tostring(message)
			if success then
				passes = passes + 1
				print("✅ " .. tostring(name) .. (tostring(message) and " • " .. tostring(message) or ""))
			else
				fails = fails + 1
				warn("⛔ " .. name .. " failed: " .. message)
			end
		end
	
		local undefinedAliases = {}
	
		for _, alias in ipairs(aliases) do
			if getGlobal(alias) == nil then
				table.insert(undefinedAliases, alias)
			end
		end
	
		if #undefinedAliases > 0 then
			undefined = undefined + 1
			warn("⚠️ " .. table.concat(undefinedAliases, ", "))
		end

		running = running - 1
	end)
end



print("\n")

print("UNC Environment Check")
print("✅ - Pass, ⛔ - Fail, ⏺️ - No test, ⚠️ - Missing aliases\n")

task.defer(function()
	repeat task.wait() until running == 0

	local rate = math.round(passes / (passes + fails) * 100)
	local outOf = passes .. " out of " .. (passes + fails)

	print("\n")

	print("UNC Summary")
	print("✅ Tested with a " .. rate .. "% success rate (" .. outOf .. ")")
	print("⛔ " .. fails .. " tests failed")
	print("⚠️ " .. undefined .. " globals are missing aliases")
end)



test("cache.invalidate", {}, function()
	local container = Instance.new("Folder")
	local part = Instance.new("Part", container)
	cache.invalidate(container:FindFirstChild("Part"))
	assert(part ~= container:FindFirstChild("Part"), "Reference `part` could not be invalidated")
end)

test("cache.iscached", {}, function()
	local part = Instance.new("Part")
	assert(cache.iscached(part), "Part should be cached")
	cache.invalidate(part)
	assert(not cache.iscached(part), "Part should not be cached")
end)

test("cache.replace", {}, function()
	local part = Instance.new("Part")
	local fire = Instance.new("Fire")
	cache.replace(part, fire)
	assert(part ~= fire, "Part was not replaced with Fire")
end)

test("cloneref", {}, function()
	local part = Instance.new("Part")
	local clone = cloneref(part)
	assert(part ~= clone, "Clone should not be equal to original")
	clone.Name = "Test"
	assert(part.Name == "Test", "Clone should have updated the original")
end)

test("compareinstances", {}, function()
	local part = Instance.new("Part")
	local clone = cloneref(part)
	assert(part ~= clone, "Clone should not be equal to original")
	assert(compareinstances(part, clone), "Clone should be equal to original when using compareinstances()")
end)



local function shallowEqual(t1, t2)
	if t1 == t2 then
		return true
	end

	local UNIQUE_TYPES = {
		["function"] = true,
		["table"] = true,
		["userdata"] = true,
		["thread"] = true,
	}

	for k, v in pairs(t1) do
		if UNIQUE_TYPES[type(v)] then
			if type(t2[k]) ~= type(v) then
				return false
			end
		elseif t2[k] ~= v then
			return false
		end
	end

	for k, v in pairs(t2) do
		if UNIQUE_TYPES[type(v)] then
			if type(t2[k]) ~= type(v) then
				return false
			end
		elseif t1[k] ~= v then
			return false
		end
	end

	return true
end

test("checkcaller", {}, function()
	assert(checkcaller(), "Main scope should return true")
end)

test("clonefunction", {}, function()
	local function test()
		return "success"
	end
	local copy = clonefunction(test)
	assert(test() == copy(), "The clone should return the same value as the original")
	assert(test ~= copy, "The clone should not be equal to the original")
end)

test("getcallingscript", {})

test("getscriptclosure", {"getscriptfunction"}, function()
	local module = game:GetService("CoreGui").RobloxGui.Modules.Common.Constants
	local constants = getrenv().require(module)
	local generated = getscriptclosure(module)()
	assert(constants ~= generated, "Generated module should not match the original")
	assert(shallowEqual(constants, generated), "Generated constant table should be shallow equal to the original")
end)

test("hookfunction", {"replaceclosure"}, function()
	local function test()
		return true
	end
	local ref = hookfunction(test, function()
		return false
	end)
	assert(test() == false, "Function should return false")
	assert(ref() == true, "Original function should return true")
	assert(test ~= ref, "Original function should not be same as the reference")
end)

test("iscclosure", {}, function()
	assert(iscclosure(print) == true, "Function 'print' should be a C closure")
	assert(iscclosure(function() end) == false, "Executor function should not be a C closure")
end)

test("islclosure", {}, function()
	assert(islclosure(print) == false, "Function 'print' should not be a Lua closure")
	assert(islclosure(function() end) == true, "Executor function should be a Lua closure")
end)

test("isexecutorclosure", {"checkclosure", "isourclosure"}, function()
	assert(isexecutorclosure(isexecutorclosure) == true, "Did not return true for an executor global")
	assert(isexecutorclosure(newcclosure(function() end)) == true, "Did not return true for an executor C closure")
	assert(isexecutorclosure(function() end) == true, "Did not return true for an executor Luau closure")
	assert(isexecutorclosure(print) == false, "Did not return false for a Roblox global")
end)

test("loadstring", {}, function()
	local animate = game:GetService("Players").LocalPlayer.Character.Animate
	local bytecode = getscriptbytecode(animate)
	local func = loadstring(bytecode)
	assert(type(func) ~= "function", "Luau bytecode should not be loadable!")
	assert(assert(loadstring("return ... + 1"))(1) == 2, "Failed to do simple math")
	assert(type(select(2, loadstring("f"))) == "string", "Loadstring did not return anything for a compiler error")
end)

test("newcclosure", {}, function()
	local function test()
		return true
	end
	local testC = newcclosure(test)
	assert(test() == testC(), "New C closure should return the same value as the original")
	assert(test ~= testC, "New C closure should not be same as the original")
	assert(iscclosure(testC), "New C closure should be a C closure")
end)



test("rconsoleclear", {"consoleclear"})

test("rconsolecreate", {"consolecreate"})

test("rconsoledestroy", {"consoledestroy"})

test("rconsoleinput", {"consoleinput"})

test("rconsoleprint", {"consoleprint"})

test("rconsolesettitle", {"rconsolename", "consolesettitle"})



test("crypt.base64encode", {"crypt.base64.encode", "crypt.base64_encode", "base64.encode", "base64_encode"}, function()
	assert(crypt.base64encode("test") == "dGVzdA==", "Base64 encoding failed")
end)

test("crypt.base64decode", {"crypt.base64.decode", "crypt.base64_decode", "base64.decode", "base64_decode"}, function()
	assert(crypt.base64decode("dGVzdA==") == "test", "Base64 decoding failed")
end)

test("crypt.encrypt", {}, function()
	local key = crypt.generatekey()
	local encrypted, iv = crypt.encrypt("test", key, nil, "CBC")
	assert(iv, "crypt.encrypt should return an IV")
	local decrypted = crypt.decrypt(encrypted, key, iv, "CBC")
	assert(decrypted == "test", "Failed to decrypt raw string from encrypted data")
end)

test("crypt.decrypt", {}, function()
	local key, iv = crypt.generatekey(), crypt.generatekey()
	local encrypted = crypt.encrypt("test", key, iv, "CBC")
	local decrypted = crypt.decrypt(encrypted, key, iv, "CBC")
	assert(decrypted == "test", "Failed to decrypt raw string from encrypted data")
end)

test("crypt.generatebytes", {}, function()
	local size = math.random(10, 100)
	local bytes = crypt.generatebytes(size)
	assert(#crypt.base64decode(bytes) == size, "The decoded result should be " .. size .. " bytes long (got " .. #crypt.base64decode(bytes) .. " decoded, " .. #bytes .. " raw)")
end)

test("crypt.generatekey", {}, function()
	local key = crypt.generatekey()
	assert(#crypt.base64decode(key) == 32, "Generated key should be 32 bytes long when decoded")
end)

test("crypt.hash", {}, function()
	local algorithms = {'sha1', 'sha384', 'sha512', 'md5', 'sha256', 'sha3-224', 'sha3-256', 'sha3-512'}
	for _, algorithm in ipairs(algorithms) do
		local hash = crypt.hash("test", algorithm)
		assert(hash, "crypt.hash on algorithm '" .. algorithm .. "' should return a hash")
	end
end)



test("debug.getconstant", {}, function()
	local function test()
		print("Hello, world!")
	end
	assert(debug.getconstant(test, 1) == "print", "First constant must be print")
	assert(debug.getconstant(test, 2) == nil, "Second constant must be nil")
	assert(debug.getconstant(test, 3) == "Hello, world!", "Third constant must be 'Hello, world!'")
end)

test("debug.getconstants", {}, function()
	local function test()
		local num = 5000 .. 50000
		print("Hello, world!", num, warn)
	end
	local constants = debug.getconstants(test)
	assert(constants[1] == 50000, "First constant must be 50000")
	assert(constants[2] == "print", "Second constant must be print")
	assert(constants[3] == nil, "Third constant must be nil")
	assert(constants[4] == "Hello, world!", "Fourth constant must be 'Hello, world!'")
	assert(constants[5] == "warn", "Fifth constant must be warn")
end)

test("debug.getinfo", {}, function()
	local types = {
		source = "string",
		short_src = "string",
		func = "function",
		what = "string",
		currentline = "number",
		name = "string",
		nups = "number",
		numparams = "number",
		is_vararg = "number",
	}
	local function test(...)
		print(...)
	end
	local info = debug.getinfo(test)
	for k, v in pairs(types) do
		assert(info[k] ~= nil, "Did not return a table with a '" .. k .. "' field")
		assert(type(info[k]) == v, "Did not return a table with " .. k .. " as a " .. v .. " (got " .. type(info[k]) .. ")")
	end
end)

test("debug.getproto", {}, function()
	local function test()
		local function proto()
			return true
		end
	end
	local proto = debug.getproto(test, 1, true)[1]
	local realproto = debug.getproto(test, 1)
	assert(proto, "Failed to get the inner function")
	assert(proto() == true, "The inner function did not return anything")
	if not realproto() then
		return "Proto return values are disabled on this executor"
	end
end)

test("debug.getprotos", {}, function()
	local function test()
		local function _1()
			return true
		end
		local function _2()
			return true
		end
		local function _3()
			return true
		end
	end
	for i in ipairs(debug.getprotos(test)) do
		local proto = debug.getproto(test, i, true)[1]
		local realproto = debug.getproto(test, i)
		assert(proto(), "Failed to get inner function " .. i)
		if not realproto() then
			return "Proto return values are disabled on this executor"
		end
	end
end)

test("debug.getstack", {}, function()
	local _ = "a" .. "b"
	assert(debug.getstack(1, 1) == "ab", "The first item in the stack should be 'ab'")
	assert(debug.getstack(1)[1] == "ab", "The first item in the stack table should be 'ab'")
end)

test("debug.getupvalue", {}, function()
	local upvalue = function() end
	local function test()
		print(upvalue)
	end
	assert(debug.getupvalue(test, 1) == upvalue, "Unexpected value returned from debug.getupvalue")
end)

test("debug.getupvalues", {}, function()
	local upvalue = function() end
	local function test()
		print(upvalue)
	end
	local upvalues = debug.getupvalues(test)
	assert(upvalues[1] == upvalue, "Unexpected value returned from debug.getupvalues")
end)

test("debug.setconstant", {}, function()
	local function test()
		return "fail"
	end
	debug.setconstant(test, 1, "success")
	assert(test() == "success", "debug.setconstant did not set the first constant")
end)

test("debug.setstack", {}, function()
	local function test()
		return "fail", debug.setstack(1, 1, "success")
	end
	assert(test() == "success", "debug.setstack did not set the first stack item")
end)

test("debug.setupvalue", {}, function()
	local function upvalue()
		return "fail"
	end
	local function test()
		return upvalue()
	end
	debug.setupvalue(test, 1, function()
		return "success"
	end)
	assert(test() == "success", "debug.setupvalue did not set the first upvalue")
end)



if isfolder and makefolder and delfolder then
	if isfolder(".tests") then
		delfolder(".tests")
	end
	makefolder(".tests")
end

test("readfile", {}, function()
	writefile(".tests/readfile.txt", "success")
	assert(readfile(".tests/readfile.txt") == "success", "Did not return the contents of the file")
end)

test("listfiles", {}, function()
	makefolder(".tests/listfiles")
	writefile(".tests/listfiles/test_1.txt", "success")
	writefile(".tests/listfiles/test_2.txt", "success")
	local files = listfiles(".tests/listfiles")
	assert(#files == 2, "Did not return the correct number of files")
	assert(isfile(files[1]), "Did not return a file path")
	assert(readfile(files[1]) == "success", "Did not return the correct files")
	makefolder(".tests/listfiles_2")
	makefolder(".tests/listfiles_2/test_1")
	makefolder(".tests/listfiles_2/test_2")
	local folders = listfiles(".tests/listfiles_2")
	assert(#folders == 2, "Did not return the correct number of folders")
	assert(isfolder(folders[1]), "Did not return a folder path")
end)

test("writefile", {}, function()
	writefile(".tests/writefile.txt", "success")
	assert(readfile(".tests/writefile.txt") == "success", "Did not write the file")
	local requiresFileExt = pcall(function()
		writefile(".tests/writefile", "success")
		assert(isfile(".tests/writefile.txt"))
	end)
	if not requiresFileExt then
		return "This executor requires a file extension in writefile"
	end
end)

test("makefolder", {}, function()
	makefolder(".tests/makefolder")
	assert(isfolder(".tests/makefolder"), "Did not create the folder")
end)

test("appendfile", {}, function()
	writefile(".tests/appendfile.txt", "su")
	appendfile(".tests/appendfile.txt", "cce")
	appendfile(".tests/appendfile.txt", "ss")
	assert(readfile(".tests/appendfile.txt") == "success", "Did not append the file")
end)

test("isfile", {}, function()
	writefile(".tests/isfile.txt", "success")
	assert(isfile(".tests/isfile.txt") == true, "Did not return true for a file")
	assert(isfile(".tests") == false, "Did not return false for a folder")
	assert(isfile(".tests/doesnotexist.exe") == false, "Did not return false for a nonexistent path (got " .. tostring(isfile(".tests/doesnotexist.exe")) .. ")")
end)

test("isfolder", {}, function()
	assert(isfolder(".tests") == true, "Did not return false for a folder")
	assert(isfolder(".tests/doesnotexist.exe") == false, "Did not return false for a nonexistent path (got " .. tostring(isfolder(".tests/doesnotexist.exe")) .. ")")
end)

test("delfolder", {}, function()
	makefolder(".tests/delfolder")
	delfolder(".tests/delfolder")
	assert(isfolder(".tests/delfolder") == false, "Failed to delete folder (isfolder = " .. tostring(isfolder(".tests/delfolder")) .. ")")
end)

test("delfile", {}, function()
	writefile(".tests/delfile.txt", "Hello, world!")
	delfile(".tests/delfile.txt")
	assert(isfile(".tests/delfile.txt") == false, "Failed to delete file (isfile = " .. tostring(isfile(".tests/delfile.txt")) .. ")")
end)

test("dofile", {})



test("isrbxactive", {"isgameactive"}, function()
	assert(type(isrbxactive()) == "boolean", "Did not return a boolean value")
end)

test("mouse1click", {})

test("mouse1press", {})

test("mouse1release", {})

test("mouse2click", {})

test("mouse2press", {})

test("mouse2release", {})

test("mousemoveabs", {})

test("mousemoverel", {})

test("mousescroll", {})


test("fireclickdetector", {}, function()
	local detector = Instance.new("ClickDetector")
	fireclickdetector(detector, 50, "MouseHoverEnter")
end)

test("getcallbackvalue", {}, function()
	local bindable = Instance.new("BindableFunction")
	local function test()
	end
	bindable.OnInvoke = test
	assert(getcallbackvalue(bindable, "OnInvoke") == test, "Did not return the correct value")
end)

test("getconnections", {}, function()
	local types = {
		Enabled = "boolean",
		ForeignState = "boolean",
		LuaConnection = "boolean",
		Function = "function",
		Thread = "thread",
		Fire = "function",
		Defer = "function",
		Disconnect = "function",
		Disable = "function",
		Enable = "function",
	}
	local bindable = Instance.new("BindableEvent")
	bindable.Event:Connect(function() end)
	local connection = getconnections(bindable.Event)[1]
	for k, v in pairs(types) do
		assert(connection[k] ~= nil, "Did not return a table with a '" .. k .. "' field")
		assert(type(connection[k]) == v, "Did not return a table with " .. k .. " as a " .. v .. " (got " .. type(connection[k]) .. ")")
	end
end)

test("getcustomasset", {}, function()
	writefile(".tests/getcustomasset.txt", "success")
	local contentId = getcustomasset(".tests/getcustomasset.txt")
	assert(type(contentId) == "string", "Did not return a string")
	assert(#contentId > 0, "Returned an empty string")
	assert(string.match(contentId, "rbxasset://") == "rbxasset://", "Did not return an rbxasset url")
end)

test("gethiddenproperty", {}, function()
	local fire = Instance.new("Fire")
	local property, isHidden = gethiddenproperty(fire, "size_xml")
	assert(property == 5, "Did not return the correct value")
	assert(isHidden == true, "Did not return whether the property was hidden")
end)

test("sethiddenproperty", {}, function()
	local fire = Instance.new("Fire")
	local hidden = sethiddenproperty(fire, "size_xml", 10)
	assert(hidden, "Did not return true for the hidden property")
	assert(gethiddenproperty(fire, "size_xml") == 10, "Did not set the hidden property")
end)

test("gethui", {}, function()
	assert(typeof(gethui()) == "Instance", "Did not return an Instance")
end)

test("getinstances", {}, function()
	assert(getinstances()[1]:IsA("Instance"), "The first value is not an Instance")
end)

test("getnilinstances", {}, function()
	assert(getnilinstances()[1]:IsA("Instance"), "The first value is not an Instance")
	assert(getnilinstances()[1].Parent == nil, "The first value is not parented to nil")
end)

test("isscriptable", {}, function()
	local fire = Instance.new("Fire")
	assert(isscriptable(fire, "size_xml") == false, "Did not return false for a non-scriptable property (size_xml)")
	assert(isscriptable(fire, "Size") == true, "Did not return true for a scriptable property (Size)")
end)

test("setscriptable", {}, function()
	local fire = Instance.new("Fire")
	local wasScriptable = setscriptable(fire, "size_xml", true)
	assert(wasScriptable == false, "Did not return false for a non-scriptable property (size_xml)")
	assert(isscriptable(fire, "size_xml") == true, "Did not set the scriptable property")
	fire = Instance.new("Fire")
	assert(isscriptable(fire, "size_xml") == false, "⚠️⚠️ setscriptable persists between unique instances ⚠️⚠️")
end)

test("setrbxclipboard", {})



test("getrawmetatable", {}, function()
	local metatable = { __metatable = "Locked!" }
	local object = setmetatable({}, metatable)
	assert(getrawmetatable(object) == metatable, "Did not return the metatable")
end)

test("hookmetamethod", {}, function()
	local object = setmetatable({}, { __index = newcclosure(function() return false end), __metatable = "Locked!" })
	local ref = hookmetamethod(object, "__index", function() return true end)
	assert(object.test == true, "Failed to hook a metamethod and change the return value")
	assert(ref() == false, "Did not return the original function")
end)

test("getnamecallmethod", {}, function()
	local method
	local ref
	ref = hookmetamethod(game, "__namecall", function(...)
		if not method then
			method = getnamecallmethod()
		end
		return ref(...)
	end)
	game:GetService("Lighting")
	assert(method == "GetService", "Did not get the correct method (GetService)")
end)

test("isreadonly", {}, function()
	local object = {}
	table.freeze(object)
	assert(isreadonly(object), "Did not return true for a read-only table")
end)

test("setrawmetatable", {}, function()
	local object = setmetatable({}, { __index = function() return false end, __metatable = "Locked!" })
	local objectReturned = setrawmetatable(object, { __index = function() return true end })
	assert(object, "Did not return the original object")
	assert(object.test == true, "Failed to change the metatable")
	if objectReturned then
		return objectReturned == object and "Returned the original object" or "Did not return the original object"
	end
end)

test("setreadonly", {}, function()
	local object = { success = false }
	table.freeze(object)
	setreadonly(object, false)
	object.success = true
	assert(object.success, "Did not allow the table to be modified")
end)



test("identifyexecutor", {"getexecutorname"}, function()
	local name, version = identifyexecutor()
	assert(type(name) == "string", "Did not return a string for the name")
	return type(version) == "string" and "Returns version as a string" or "Does not return version"
end)

test("lz4compress", {}, function()
	local raw = "Hello, world!"
	local compressed = lz4compress(raw)
	assert(type(compressed) == "string", "Compression did not return a string")
	assert(lz4decompress(compressed, #raw) == raw, "Decompression did not return the original string")
end)

test("lz4decompress", {}, function()
	local raw = "Hello, world!"
	local compressed = lz4compress(raw)
	assert(type(compressed) == "string", "Compression did not return a string")
	assert(lz4decompress(compressed, #raw) == raw, "Decompression did not return the original string")
end)

test("messagebox", {})

test("queue_on_teleport", {"queueonteleport"})

test("request", {"http.request", "http_request"}, function()
	local response = request({
		Url = "https://httpbin.org/user-agent",
		Method = "GET",
	})
	assert(type(response) == "table", "Response must be a table")
	assert(response.StatusCode == 200, "Did not return a 200 status code")
	local data = game:GetService("HttpService"):JSONDecode(response.Body)
	assert(type(data) == "table" and type(data["user-agent"]) == "string", "Did not return a table with a user-agent key")
	return "User-Agent: " .. data["user-agent"]
end)

test("setclipboard", {"toclipboard"})

test("setfpscap", {}, function()
	local renderStepped = game:GetService("RunService").RenderStepped
	local function step()
		renderStepped:Wait()
		local sum = 0
		for _ = 1, 5 do
			sum = sum + 1 / renderStepped:Wait()
		end
		return math.round(sum / 5)
	end
	setfpscap(60)
	local step60 = step()
	setfpscap(0)
	local step0 = step()
	return step60 .. "fps @60 • " .. step0 .. "fps @0"
end)



test("getgc", {}, function()
	local gc = getgc()
	assert(type(gc) == "table", "Did not return a table")
	assert(#gc > 0, "Did not return a table with any values")
end)

test("getgenv", {}, function()
	getgenv().__TEST_GLOBAL = true
	assert(__TEST_GLOBAL, "Failed to set a global variable")
	getgenv().__TEST_GLOBAL = nil
end)

test("getloadedmodules", {}, function()
	local modules = getloadedmodules()
	assert(type(modules) == "table", "Did not return a table")
	assert(#modules > 0, "Did not return a table with any values")
	assert(typeof(modules[1]) == "Instance", "First value is not an Instance")
	assert(modules[1]:IsA("ModuleScript"), "First value is not a ModuleScript")
end)

test("getrenv", {}, function()
	assert(_G ~= getrenv()._G, "The variable _G in the executor is identical to _G in the game")
end)

test("getrunningscripts", {}, function()
	local scripts = getrunningscripts()
	assert(type(scripts) == "table", "Did not return a table")
	assert(#scripts > 0, "Did not return a table with any values")
	assert(typeof(scripts[1]) == "Instance", "First value is not an Instance")
	assert(scripts[1]:IsA("ModuleScript") or scripts[1]:IsA("LocalScript"), "First value is not a ModuleScript or LocalScript")
end)

test("getscriptbytecode", {"dumpstring"}, function()
	local animate = game:GetService("Players").LocalPlayer.Character.Animate
	local bytecode = getscriptbytecode(animate)
	assert(type(bytecode) == "string", "Did not return a string for Character.Animate (a " .. animate.ClassName .. ")")
end)

test("getscripthash", {}, function()
	local animate = game:GetService("Players").LocalPlayer.Character.Animate:Clone()
	local hash = getscripthash(animate)
	local source = animate.Source
	animate.Source = "print('Hello, world!')"
	task.defer(function()
		animate.Source = source
	end)
	local newHash = getscripthash(animate)
	assert(hash ~= newHash, "Did not return a different hash for a modified script")
	assert(newHash == getscripthash(animate), "Did not return the same hash for a script with the same source")
end)

test("getscripts", {}, function()
	local scripts = getscripts()
	assert(type(scripts) == "table", "Did not return a table")
	assert(#scripts > 0, "Did not return a table with any values")
	assert(typeof(scripts[1]) == "Instance", "First value is not an Instance")
	assert(scripts[1]:IsA("ModuleScript") or scripts[1]:IsA("LocalScript"), "First value is not a ModuleScript or LocalScript")
end)

test("getsenv", {}, function()
	local animate = game:GetService("Players").LocalPlayer.Character.Animate
	local env = getsenv(animate)
	assert(type(env) == "table", "Did not return a table for Character.Animate (a " .. animate.ClassName .. ")")
	assert(env.script == animate, "The script global is not identical to Character.Animate")
end)

test("getthreadidentity", {"getidentity", "getthreadcontext"}, function()
	assert(type(getthreadidentity()) == "number", "Did not return a number")
end)

test("setthreadidentity", {"setidentity", "setthreadcontext"}, function()
	setthreadidentity(3)
	assert(getthreadidentity() == 3, "Did not set the thread identity")
end)



test("Drawing", {})

test("Drawing.new", {}, function()
	local drawing = Drawing.new("Square")
	drawing.Visible = false
	local canDestroy = pcall(function()
		drawing:Destroy()
	end)
	assert(canDestroy, "Drawing:Destroy() should not throw an error")
end)

test("Drawing.Fonts", {}, function()
	assert(Drawing.Fonts.UI == 0, "Did not return the correct id for UI")
	assert(Drawing.Fonts.System == 1, "Did not return the correct id for System")
	assert(Drawing.Fonts.Plex == 2, "Did not return the correct id for Plex")
	assert(Drawing.Fonts.Monospace == 3, "Did not return the correct id for Monospace")
end)

test("isrenderobj", {}, function()
	local drawing = Drawing.new("Image")
	drawing.Visible = true
	assert(isrenderobj(drawing) == true, "Did not return true for an Image")
	assert(isrenderobj(newproxy()) == false, "Did not return false for a blank table")
end)

test("getrenderproperty", {}, function()
	local drawing = Drawing.new("Image")
	drawing.Visible = true
	assert(type(getrenderproperty(drawing, "Visible")) == "boolean", "Did not return a boolean value for Image.Visible")
	local success, result = pcall(function()
		return getrenderproperty(drawing, "Color")
	end)
	if not success or not result then
		return "Image.Color is not supported"
	end
end)

test("setrenderproperty", {}, function()
	local drawing = Drawing.new("Square")
	drawing.Visible = true
	setrenderproperty(drawing, "Visible", false)
	assert(drawing.Visible == false, "Did not set the value for Square.Visible")
end)

test("cleardrawcache", {}, function()
	cleardrawcache()
end)



test("WebSocket", {})

test("WebSocket.connect", {}, function()
	local types = {
		Send = "function",
		Close = "function",
		OnMessage = {"table", "userdata"},
		OnClose = {"table", "userdata"},
	}
	local ws = WebSocket.connect("ws://echo.websocket.events")
	assert(type(ws) == "table" or type(ws) == "userdata", "Did not return a table or userdata")
	for k, v in pairs(types) do
		if type(v) == "table" then
			assert(table.find(v, type(ws[k])), "Did not return a " .. table.concat(v, ", ") .. " for " .. k .. " (a " .. type(ws[k]) .. ")")
		else
			assert(type(ws[k]) == v, "Did not return a " .. v .. " for " .. k .. " (a " .. type(ws[k]) .. ")")
		end
	end
	ws:Close()
end)
print("\n")
print("Made by Bdokkx | Join discord.gg/ronix, discord.gg/getgalaxy")

wait(2)
print("\n")
print("\n")
print("_________________________________________________________________________________________________________________________________________")
warn("                                                 running Vuln test in 5 seconds")
wait(5) 

--[[
	WARNING: Heads up! This script has not been verified by ScriptBlox. Use at your own risk!
]]
local passes, fails, undefined = 0, 0, 0
local running = 0

local function test(name: string, callback_or_message: any, message: string): ()
    running += 1
    if type(callback_or_message) == 'string' then
        undefined += 1
        print("⏺️ " .. name.. ": ".. callback_or_message)
    else
        local timeout = 3
        local succeeded = false
        function starttest()
            task.spawn(function()
                local success: boolean, err: string = pcall(callback_or_message)
            
                if success or not success and err:match('Argument %d missing or nil') or err:find('Expected \':\' not \'.\' calling member function') then
                    fails += 1
                    warn("⛔ " .. name .. ": " .. message)
                elseif not success and string.find(err, 'current thread cannot') and string.find(err, 'lacking capability') then
                    undefined += 1
                    print("⏺️ " .. name.. ": Executor cannot access due to thread identity")
                else
                    local _, i = err:find(":%d+: ") 
                    if i then 
                        err = err:sub(i + 1)
                    end
                    passes += 1
                    print("✅ " .. name.. ": ".. err)
                end
                succeeded = true
            end)
        end

        coroutine.wrap(starttest)()
        local now = tick()
        repeat wait() until succeeded or tick() - now >= timeout

        if not succeeded then
            undefined += 1
            print("⏺️ " .. name.. ": Test Timeout")
        end
    end

    running -= 1
end

local getexecname = identifyexecutor or getexecutorname or whatexecutor or function() return 'Unknown Executor' end
print("Executor Vulnerability Check - ".. getexecname())
print("✅ - Pass, ⛔ - Fail, ⏺️ - No test")

-- ScriptContext
print()
test("ScriptContext.AddCoreScriptLocal", function()
	game:GetService('ScriptContext'):AddCoreScriptLocal()
end, 'This function can be used to create a new CoreScript, from which people can escape the executor environment')
test("ScriptContext.SaveScriptProfilingData", function()
	game:GetService('ScriptContext'):SaveScriptProfilingData()
end, 'This function can be used to create a file on your PC and return the path')

-- ScriptProfilerService
print()
test("ScriptProfilerService.SaveScriptProfilingData", function()
	game:GetService('ScriptProfilerService'):SaveScriptProfilingData()
end, 'This function can be used to create a file on your PC and return the path')

-- MarketplaceService (yes theres a lot)
print()
test("MarketplaceService.GetRobuxBalance", function()
	game:GetService('MarketplaceService'):GetRobuxBalance()
end, 'This function can get your Robux balance')

test("MarketplaceService.GetUserSubscriptionDetailsInternalAsync", function()
	game:GetService('MarketplaceService'):GetUserSubscriptionDetailsInternalAsync()
end, 'This function can get a player\'s subscription details')

test("MarketplaceService.GetUserSubscriptionStatusAsync", function()
	game:GetService('MarketplaceService'):GetUserSubscriptionStatusAsync()
end, 'This function can get a player\'s subscription status')

test("MarketplaceService.PerformBulkPurchase", function()
	game:GetService('MarketplaceService'):PerformBulkPurchase()
end, 'This function can be used to perform a bulk purchase')

test("MarketplaceService.PerformCancelSubscription", function()
	game:GetService('MarketplaceService'):PerformCancelSubscription()
end, 'This function can be used to cancel the player\'s subscription')

test("MarketplaceService.PerformPurchase", function()
	game:GetService('MarketplaceService'):PerformPurchase()
end, 'This function can be used to perform a Roblox purchase')

test("MarketplaceService.PerformPurchaseV2", function()
	game:GetService('MarketplaceService'):PerformPurchaseV2()
end, 'This function can be used to perform a Roblox purchase')

test("MarketplaceService.PerformSubscriptionPurchase", function()
	game:GetService('MarketplaceService'):PerformSubscriptionPurchase()
end, 'This function can be used to perform a subscription purchase')

test("MarketplaceService.PerformSubscriptionPurchaseV2", function()
	game:GetService('MarketplaceService'):PerformSubscriptionPurchaseV2()
end, 'This function can be used to perform a subscription purchase')

test("MarketplaceService.PrepareCollectiblesPurchase", function()
	game:GetService('MarketplaceService'):PrepareCollectiblesPurchase()
end, 'This function prepares a collectible purchase')

test("MarketplaceService.PromptBulkPurchase", function()
	game:GetService('MarketplaceService'):PromptBulkPurchase()
end, 'This function prompts a bulk purchase')

test("MarketplaceService.PromptBundlePurchase", function()
	game:GetService('MarketplaceService'):PromptBundlePurchase()
end, 'This function prompts a bundle purchase')

test("MarketplaceService.PromptCancelSubscription", function()
	game:GetService('MarketplaceService'):PromptCancelSubscription()
end, 'This function prompts a subscription cancel')

test("MarketplaceService.PromptCollectiblesPurchase", function()
	game:GetService('MarketplaceService'):PromptCollectiblesPurchase()
end, 'This function prompts a collectibles purchase')

test("MarketplaceService.PromptGamePassPurchase", function()
	game:GetService('MarketplaceService'):PromptGamePassPurchase()
end, 'This function prompts a Gamepass purchase')

test("MarketplaceService.PromptNativePurchase", function()
	game:GetService('MarketplaceService'):PromptNativePurchase()
end, 'This function prompts a purchase')

test("MarketplaceService.PromptNativePurchaseWithLocalPlayer", function()
	game:GetService('MarketplaceService'):PromptNativePurchaseWithLocalPlayer()
end, 'This function prompts a purchase')

test("MarketplaceService.PromptPremiumPurchase", function()
	game:GetService('MarketplaceService'):PromptPremiumPurchase()
end, 'This function prompts a Premium Purchase')

test("MarketplaceService.PromptProductPurchase", function()
	game:GetService('MarketplaceService'):PromptProductPurchase()
end, 'This function prompts a purchase')

test("MarketplaceService.PromptPurchase", function()
	game:GetService('MarketplaceService'):PromptPurchase()
end, 'This function prompts a purchase')

test("MarketplaceService.PromptRobloxPurchase", function()
	game:GetService('MarketplaceService'):PromptRobloxPurchase()
end, 'This function prompts a purchase')

test("MarketplaceService.PromptSubscriptionPurchase", function()
	game:GetService('MarketplaceService'):PromptSubscriptionPurchase()
end, 'This function prompts a subscription purchase')

test("MarketplaceService.PromptThirdPartyPurchase", function()
	game:GetService('MarketplaceService'):PromptThirdPartyPurchase()
end, 'This function prompts a 3rd party purchase')

-- Players
print()
test("Players.ReportAbuse", function()
    game:GetService('Players'):ReportAbuse(game:GetService('Players').LocalPlayer)
end, 'This function allows a bad actor to mass report you')

test("Players.ReportAbuseV3", function()
    game:GetService('Players'):ReportAbuseV3(game:GetService('Players').LocalPlayer)
end, 'This function allows a bad actor to mass report you')

-- CoreGui
print()
test("CoreGui.TakeScreenshot", function()
    game:GetService('CoreGui'):TakeScreenshot()
end, 'This function allows a bad actor to take a screenshot and flood your PC storage')

test("CoreGui.ToggleRecording", function()
    game:GetService('CoreGui'):ToggleRecording()
end, 'This function allows a bad actor to toggle a recording and flood your PC storage')
    
-- BrowserService
print()
test("BrowserService.OpenBrowserWindow", function()
    game:GetService('BrowserService'):OpenBrowserWindow()
end, 'This function allows a bad actor to open a in-game browser window')
    
test("BrowserService.ExecuteJavaScript", function()
    game:GetService('BrowserService'):ExecuteJavaScript()
end, 'This function allows a bad actor to execute JavaScript')
    
test("BrowserService.ReturnToJavaScript", function()
    game:GetService('BrowserService'):ReturnToJavaScript()
end, 'This function allows a bad actor to execute JavaScript')
    
test("BrowserService.SendCommand", function()
    game:GetService('BrowserService'):SendCommand()
end, 'This function allows a bad actor to send a command to a browser window')
    
test("BrowserService.OpenNativeOverlay", function()
    game:GetService('BrowserService').OpenNativeOverlay()
end, 'This function allows a bad actor to open an overlay window')
    
test("BrowserService.OpenWeChatAuthWindow", function()
    game:GetService('BrowserService').OpenWeChatAuthWindow()
end, 'This function allows a bad actor to open a WeChat Auth window, allowing them to access any Roblox webpage')
    
test("BrowserService.EmitHybridEvent", function()
    game:GetService('BrowserService'):EmitHybridEvent()
end, 'This function allows a bad actor to run a command on a browser window')

-- GuiService
print()
test('GuiService.OpenBrowserWindow', function()
    game:GetService('GuiService'):OpenBrowserWindow()
end, 'This function allows a bad actor to open a browser window')

-- LinkingService
print()
test('LinkingService.OpenUrl', function()
    game:GetService('LinkingService'):OpenUrl()
end, 'This function can be used to launch a local file or a command.')

-- OpenCloudService
print()
test('OpenCloudService.HttpRequestAsync', function()
    game:GetService('OpenCloudService'):HttpRequestAsync()
end, 'This function can be used to make an authenticated request')

-- HttpService
print()
test('HttpService.RequestInternal', function()
    game:GetService('HttpService'):RequestInternal()
end, 'This function can be used to request to a Roblox API')

-- HttpRbxApiService
print()
test('HttpRbxApiService.GetAsync', function()
    game:GetService('HttpRbxApiService'):GetAsync()
end, 'This function can be used to make a request to Roblox APIs')

test('HttpRbxApiService.GetAsyncFullUrl', function()
    game:GetService('HttpRbxApiService'):GetAsyncFullUrl()
end, 'This function can be used to make a request to Roblox APIs')

test('HttpRbxApiService.PostAsync', function()
    game:GetService('HttpRbxApiService'):PostAsync()
end, 'This function can be used to make a request to Roblox APIs')

test('HttpRbxApiService.PostAsyncFullUrl', function()
    game:GetService('HttpRbxApiService'):PostAsyncFullUrl()
end, 'This function can be used to make a request to Roblox APIs')
    
test('HttpRbxApiService.RequestAsync', function()
    game:GetService('HttpRbxApiService'):RequestAsync()
end, 'This function can be used to make a request to Roblox APIs')
    
test('HttpRbxApiService.RequestLimitedAsync', function()
    game:GetService('HttpRbxApiService'):RequestLimitedAsync()
end, 'This function can be used to make a request to Roblox APIs')
    
-- TestService
print()
test('TestService.Run', function()
    game:GetService('TestService'):Run()
end, 'This function can be used, paired with queueonteleport, to run malicious code with the executor thread identity, but outside of the environment.')
    
-- DataModel
print()
test("game.OpenScreenshotsFolder", function()
    game:OpenScreenshotsFolder()
end, 'This function allows a bad actor to spam open the screenshots folder')

test("game.OpenVideosFolder", function()
    game:OpenVideosFolder()
end, 'This function allows a bad actor to spam open the screenshots folder')

test("game.Load", function()
    game:Load()
end, 'This function allows someone to load an object of a URL, the actual functionaility is not very docummented')

-- CaptureService
print()
test("CaptureService.CaptureScreenshot", function()
    game:GetService('CaptureService'):CaptureScreenshot()
end, 'This function allows someone to capture a screenshot and do a function with it')
    
test("CaptureService.CreatePostAsync", function()
    game:GetService('CaptureService'):CreatePostAsync()
end, 'This function allows someone to post a capture you made')

test("CaptureService.DeleteCapture", function()
    game:GetService('CaptureService'):DeleteCapture()
end, 'This function allows someone to delete a file from your system')

test("CaptureService.DeleteCapturesAsync", function()
    game:GetService('CaptureService'):DeleteCapturesAsync()
end, 'This function allows someone to delete files from your system')   
    
test("CaptureService.GetCaptureFilePathAsync", function()
    game:GetService('CaptureService'):GetCaptureFilePathAsync()
end, 'This function allows someone to get the path of a saved capture')   

test("CaptureService.SaveCaptureToExternalStorage", function()
    game:GetService('CaptureService'):SaveCaptureToExternalStorage()
end, 'This function allows someone to save a capture')   
    
test("CaptureService.SaveCapturesToExternalStorageAsync", function()
    game:GetService('CaptureService'):SaveCapturesToExternalStorageAsync()
end, 'This function allows someone to save captures')   
    
test("CaptureService.SaveCapturesToExternalStorageAsync", function()
    game:GetService('CaptureService'):SaveCapturesToExternalStorageAsync()
end, 'This function allows someone to save captures')   

test("CaptureService.GetCaptureUploadDataAsync", function()
    game:GetService('CaptureService'):GetCaptureUploadDataAsync()
end, 'This function allows someone to get the data of a capture')   
    
test("CaptureService.PostToFeedAsync", function()
    game:GetService('CaptureService'):PostToFeedAsync()
end, 'This function allows someone to post a capture to a feed (?)')   
    
test("CaptureService.RetrieveCaptures", function()
    game:GetService('CaptureService'):RetrieveCaptures()
end, 'This function allows someone to retrieve all made captures')   
      
test("CaptureService.SaveScreenshotCapture", function()
    game:GetService('CaptureService'):SaveScreenshotCapture()
end, 'This function allows someone to save a screenshot')   


-- MessageBusService
print()
test("MessageBusService.Call", function()
    game:GetService('MessageBusService'):Call()
end, 'This calls something')

test("MessageBusService.GetLast", function()
    game:GetService('MessageBusService'):GetLast()
end, 'This gets the data of the last call')

test("MessageBusService.GetMessageId", function()
    game:GetService('MessageBusService'):GetMessageId()
end, 'This gets the message id of call')

test("MessageBusService.GetProtocolMethodRequestMessageId", function()
    game:GetService('MessageBusService'):GetProtocolMethodRequestMessageId()
end, 'This gets the protocol method of the lastest request\'s message id')

test("MessageBusService.GetProtocolMethodResponseMessageId", function()
    game:GetService('MessageBusService'):GetProtocolMethodResponseMessageId()
end, 'This gets the protocol method of the lastest response\'s message id')

test("MessageBusService.MakeRequest", function()
    game:GetService('MessageBusService'):MakeRequest()
end, 'This makes a request')

test("MessageBusService.Publish", function()
    game:GetService('MessageBusService'):Publish()
end, 'This can publish something and can be used to RCE')

test("MessageBusService.PublishProtocolMethodRequest", function()
    game:GetService('MessageBusService'):PublishProtocolMethodRequest()
end, 'This publishes a protocol method request')

test("MessageBusService.PublishProtocolMethodResponse", function()
    game:GetService('MessageBusService'):PublishProtocolMethodResponse()
end, 'This responds to a protocol method request')

test("MessageBusService.Subscribe", function()
    game:GetService('MessageBusService'):Subscribe()
end, 'This subscribes to something')

test("MessageBusService.SubscribeToProtocolMethodRequest", function()
    game:GetService('MessageBusService'):SubscribeToProtocolMethodRequest()
end, 'This subscribes to a request')

test("MessageBusService.SubscribeToProtocolMethodResponse", function()
    game:GetService('MessageBusService'):SubscribeToProtocolMethodResponse()
end, 'This subscribes in response to a protocol method request')

-- AccountService
print()
test('AccountService.GetCredentialsHeaders', function()
    game:GetService("AccountService"):GetCredentialsHeaders()
end, 'This gets the credentials headers')
test('AccountService.GetCredentialsHeaders', function()
    game:GetService("AccountService"):GetDeviceAccessToken()
end, 'This gets the device access token')
test('AccountService.GetDeviceIntegrityToken', function()
    game:GetService("AccountService"):GetDeviceIntegrityToken()
end, 'This gets the device integrity token')
test('AccountService.GetDeviceIntegrityTokenYield', function()
    game:GetService("AccountService"):GetDeviceIntegrityTokenYield()
end, 'This gets the device integrity token')


-- AvatarEditorService
print()
test("AvatarEditorService.NoPromptCreateOutfit", function()
    game:GetService("AvatarEditorService"):NoPromptCreateOutfit()
end, 'This function creates an outfit on your account')
test("AvatarEditorService.NoPromptDeleteOutfit", function()
    game:GetService("AvatarEditorService"):NoPromptCreateOutfit()
end, 'This function deletes an outfit on your account')
test("AvatarEditorService.NoPromptRenameOutfit", function()
    game:GetService("AvatarEditorService"):NoPromptRenameOutfit()
end, 'This function renames an outfit on your account')
test("AvatarEditorService.NoPromptSaveAvatar", function()
    game:GetService("AvatarEditorService"):NoPromptSaveAvatar()
end, 'This function saves an outfit on your account')
test("AvatarEditorService.NoPromptSaveAvatarThumbnailCustomization", function()
    game:GetService("AvatarEditorService"):NoPromptSaveAvatarThumbnailCustomization()
end, 'This function saves an outfit\'s customization on your account')
test("AvatarEditorService.NoPromptSetFavorite", function()
    game:GetService("AvatarEditorService"):NoPromptSetFavorite()
end, 'This function sets a favorite item on your account')
test("AvatarEditorService.NoPromptUpdateOutfit", function()
    game:GetService("AvatarEditorService"):NoPromptUpdateOutfit()
end, 'This function updates an outfit on your account')
test("AvatarEditorService.PerformCreateOutfitWithDescription", function()
    game:GetService("AvatarEditorService"):PerformCreateOutfitWithDescription()
end, 'This function creates an outfit on your account')
test("AvatarEditorService.PerformDeleteOutfit", function()
    game:GetService("AvatarEditorService"):PerformDeleteOutfit()
end, 'This function deletes an outfit on your account')
test("AvatarEditorService.PerformRenameOutfit", function()
    game:GetService("AvatarEditorService"):PerformRenameOutfit()
end, 'This function renames an outfit on your account')
test("AvatarEditorService.PerformSaveAvatarWithDescription", function()
    game:GetService("AvatarEditorService"):PerformSaveAvatarWithDescription()
end, 'This function saves an avatar on your account')
test("AvatarEditorService.PerformSetFavorite", function()
    game:GetService("AvatarEditorService"):PerformSetFavorite()
end, 'This function sets a favorite on your account')
test("AvatarEditorService.PerformUpdateOutfit", function()
    game:GetService("AvatarEditorService"):PerformUpdateOutfit()
end, 'This function performs an outfit update on your account')
test("AvatarEditorService.PromptCreateOutfit", function()
    game:GetService("AvatarEditorService"):PromptCreateOutfit()
end, 'This function prompts a create outfit dialog')
test("AvatarEditorService.PromptDeleteOutfit", function()
    game:GetService("AvatarEditorService"):PromptDeleteOutfit()
end, 'This function prompts a delete outfit dialog')
test("AvatarEditorService.PromptRenameOutfit", function()
    game:GetService("AvatarEditorService"):PromptRenameOutfit()
end, 'This function prompts a rename outfit dialog')
test("AvatarEditorService.PromptSaveAvatar", function()
    game:GetService("AvatarEditorService"):PromptSaveAvatar()
end, 'This function prompts a save avatar dialog')
test("AvatarEditorService.PromptSetFavorite", function()
    game:GetService("AvatarEditorService"):PromptSetFavorite()
end, 'This function prompts a favorite dialog')
test("AvatarEditorService.PromptUpdateOutfit", function()
    game:GetService("AvatarEditorService"):PromptUpdateOutfit()
end, 'This function prompts an update outfit dialog')

print()
if game:GetService("RunService"):IsStudio() then
    test('StudioService.OpenInBrowser_DONOTUSE', function()
        game:GetService("StudioService"):OpenInBrowser_DONOTUSE()
    end, 'This Studio-only function allows somebody to execute commands on your PC')
    test('StudioService.TryInstallPlugin', function()
        game:GetService("StudioService"):TryInstallPlugin()
    end, 'This Studio-only function allows somebody to install a plugin, which could have malicious code')
    test('StudioService.PromptImportFile', function()
        game:GetService("StudioService"):PromptImportFile()
    end, 'This Studio-only function allows somebody to prompt a file browser')
    test('StudioService.PromptImportFiles', function()
        game:GetService("StudioService"):PromptImportFiles()
    end, 'This Studio-only function allows somebody to prompt a file browser')
    test('StudioService.UninstallPlugin', function()
        game:GetService("StudioService"):UninstallPlugin()
    end, 'This Studio-only function allows somebody to uninstall a plugin')
else
    test('StudioService.OpenInBrowser_DONOTUSE', 'Not in Studio')
    test('StudioService.TryInstallPlugin', 'Not in Studio')
    test('StudioService.PromptImportFile', 'Not in Studio')
    test('StudioService.PromptImportFiles', 'Not in Studio')
    test('StudioService.UninstallPlugin', 'Not in Studio')
end
    
print()
local success = true
if pcall(function() game:HttpGet('https://google.com') end) == true then
    test('game.HttpGet | Roblox API', function()
        local RobloxVulnerableAPIS = {'https://accountinformation.roblox.com', 'https://accountsettings.roblox.com', 'https://twostepverification.roblox.com', 'https://trades.roblox.com', 'https://billing.roblox.com', 'https://economy.roblox.com', 'https://auth.roblox.com', 'https://accountinformation.roproxy.com', 'https://accountsettings.roproxy.com', 'https://twostepverification.roproxy.com', 'https://trades.roproxy.com', 'https://billing.roproxy.com', 'https://economy.roproxy.com', 'https://auth.roproxy.com'}
        for i,v in pairs(RobloxVulnerableAPIS) do
            local s,e = pcall(function() game:HttpGet(v) end)
            if s then
                success = false
                break
            end
        end
        if success then
            error("Executor did not access the function")
        end
    end, "Executor requested to a Vulnerable Roblox API")
else test('game.HttpGet | Roblox API', 'Executor does not support function') end
if pcall(function() game:HttpPost('https://google.com', '') end) == true then
    test('game.HttpPost | Roblox API', function()
        local RobloxVulnerableAPIS = {'https://accountinformation.roblox.com', 'https://accountsettings.roblox.com', 'https://twostepverification.roblox.com', 'https://trades.roblox.com', 'https://billing.roblox.com', 'https://economy.roblox.com', 'https://auth.roblox.com', 'https://accountinformation.roproxy.com', 'https://accountsettings.roproxy.com', 'https://twostepverification.roproxy.com', 'https://trades.roproxy.com', 'https://billing.roproxy.com', 'https://economy.roproxy.com', 'https://auth.roproxy.com'}
        for i,v in pairs(RobloxVulnerableAPIS) do
            local s,e = pcall(function() game:HttpPost(v, '') end)
            if s then
                success = false
                break
            end
        end
        if success then
            error("Executor did not access the function")
        end
    end, "Executor requested to a Vulnerable Roblox API")
else test('game.HttpPost | Robux API', 'Executor does not support function') end
if pcall(function() request({ Url = 'https://google.com', Method = 'GET'}) end) == true then
    test('request | Roblox API', function()
        local RobloxVulnerableAPIS = {'https://accountinformation.roblox.com', 'https://accountsettings.roblox.com', 'https://twostepverification.roblox.com', 'https://trades.roblox.com', 'https://billing.roblox.com', 'https://economy.roblox.com', 'https://auth.roblox.com', 'https://accountinformation.roproxy.com', 'https://accountsettings.roproxy.com', 'https://twostepverification.roproxy.com', 'https://trades.roproxy.com', 'https://billing.roproxy.com', 'https://economy.roproxy.com', 'https://auth.roproxy.com'}
        for i,v in pairs(RobloxVulnerableAPIS) do
            local s,_ = pcall(function() request({ Url = v, Method = 'GET'}) end)
            if s then
                success = false
                break
            end
        end
        if success then
            error("Executor did not access the function")
        end
    end, "Executor requested to a Vulnerable Roblox API")
else test('request | Roblox API', 'Executor does not support function') end
-- File System
print()
local listfiles = listfiles or list_files
if listfiles then
    test("listfiles | C:\\ Access", function()
        local failed
        for i,v in pairs(listfiles("C:\\")) do
            if tostring(v) == 'Windows' then
                failed = true
                break
            end
        end
        if not failed then
            error("Executor didn't access C:\\ Disk")
        end
    end, 'People are able to access all files on your PC')
else
    test('listfiles | C:\\ Access', 'Function not supported')
end

local writefile = writefile or write_file
local isfile = isfile or is_file
if (writefile and isfile) then
    test("writefile | Dangerous extension", function()
        local failed
        writefile('test.bat', "test")
        if isfile('test.bat') then 
            failed = true
        end
        if not failed then
            error("Executor didn't create the dangerous file")
        end
    end, 'People are able to create files with malicious extensions')
else
    test('writefile | Dangerous extension', 'Functions not supported')
end

-- Protection Bypasses
print()
test('Bypassing Blocked Services with Empty Characters', function()
    local s,e = pcall(game:GetService('ScriptContext\0').AddCoreScriptLocal, game:GetService('ScriptContext\0'))
    if s or e:lower():find('argument') and e:lower():find('missing or nil') or e:lower():find('current thread cannot') and e:lower():find('lacking capability') then
        return nil
	end
    error("Executor did not access the blocked function")
end, 'WARNING: This means your executor is vulnerable to nearly all vulnerabilities') 
	test('Bypassing protection by accessing an unprotected environment', function()
	    local old = getfenv()
	    local oldgame = game
	
	    setfenv(1, getfenv(print))
	    getfenv().game = nil
	    local s,e = pcall(game:GetService('ScriptContext').AddCoreScriptLocal)
		if s or string.find(e:lower(), 'argument') and string.find(e:lower(), 'missing or nil') or string.find(e:lower(), 'current thread cannot') and string.find(e:lower(), 'lacking capability') then
	        getfenv().game = oldgame
	        setfenv(1, old)
			return nil
		end
	    getfenv().game = oldgame
	    setfenv(1, old)
	    error("Executor did not access the blocked function")
	end, 'WARNING: This means your executor is vulnerable to all vulnerabilities')
	test("Bypassing protection by accessing the parent of Workspace", function()
		local oldgame = game
		getfenv().game = workspace.Parent
		local failed = false
		local _, callback = pcall(game:GetService('ScriptContext').AddCoreScriptLocal)
		if callback:match("Argument %d missing or nil") or callback:find("Expected ':' not '.' calling member function") or callback:lower():find('cannot call') and callback:lower():find('lacking capability') then
			failed = true
		end
		getfenv().game = oldgame
		if not failed then
			error("Executor did not access the blocked function")
		end
	end, "WARNING: This means your executor is vulnerable to nearly all vulnerabilities")


wait()
loadstring(game:HttpGetAsync("https://pastebin.com/raw/iXWBeKic"))()

local rate = math.round(passes / (passes + fails) * 100)
local outOf = passes .. " out of " .. (passes + fails)

print("\n")

print("Vulnerability Test Summary - ".. getexecname())
print("✅ Tested with a " .. rate .. "% mitigations rate (" .. outOf .. ")")
print("⛔ " .. fails .. " vulnerabilities not mitigated")
print("⏺️ " .. undefined .. " vulnerabilities not tested")


print("\n")
print("Done with all test!")
print("Made by Bdokkx | Join discord.gg/ronix, discord.gg/getgalaxy")
