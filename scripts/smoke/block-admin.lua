-- Smoke-test script: block /admin and everything under it, allow the rest.
function on_request_headers()
    local uri = request.uri
    if uri == "/admin" or uri:sub(1, 7) == "/admin/" or uri:sub(1, 7) == "/admin?" then
        return { decision = "block", status = 403, body = "blocked by lua" }
    end
    return { decision = "allow", add_request_headers = { ["X-Lua-Smoke"] = "1" } }
end
