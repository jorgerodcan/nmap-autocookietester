local httpspider = require "httpspider"
local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local tab = require "tab"
local table = require "table"
local urlhandler = require "url"

description = [[
Spiders a web site to find web pages requiring form-based or HTTP-based authentication. The results are returned in a table with each url and the
detected method.
]]

---
-- @usage
-- nmap -p 80|443 --script https-auth-finder <ip>
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | http-auth-finder:
-- |   url                                   method
-- |   http://192.168.1.162/auth1/index.html  HTTP: Basic, Digest, Negotiate
-- |_  http://192.168.1.162/auth2/index.html  FORM
--
-- @args http-auth-finder.maxdepth the maximum amount of directories beneath
--       the initial url to spider. A negative value disables the limit.
--       (default: 3)
-- @args http-auth-finder.maxpagecount the maximum amount of pages to visit.
--       A negative value disables the limit (default: 20)
-- @args http-auth-finder.url the url to start spidering. This is a URL
--       relative to the scanned host eg. /default.html (default: /)
-- @args http-auth-finder.withinhost only spider URLs within the same host.
--       (default: true)
-- @args http-auth-finder.withindomain only spider URLs within the same
--       domain. This widens the scope from <code>withinhost</code> and can
--       not be used in combination. (default: false)

author = "JRC & RLM"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}


portrule = shortport.http or shortport.https

local function parseAuthentication(resp)
  local cookieheaderarray = resp.cookies
  if ( not(cookieheaderarray) ) then
    return false, "Server returned no cookies."
  end

  return true, cookieheaderarray
end

action = function(host, port)

  -- create a new crawler instance
  local crawler = httpspider.Crawler:new( host, port, nil, { scriptname = SCRIPT_NAME } )

  if ( not(crawler) ) then
    return
  end

  -- create a table entry in the registry
  nmap.registry.cookie_table = nmap.registry.auth_urls or {}
  crawler:set_timeout(10000)

  local auth_urls = tab.new(4)
  tab.addrow(auth_urls, "Cookie", "Vuln-Type", "Vuln-Value", "From (attributes trimmed)")
  tab.addrow(auth_urls, "------",  "---------", "----------", "-------------------------")

  local cookie_table = {}
  while(true) do
    local status, r = crawler:crawl()
    if ( not(status) ) then
      if ( r.err ) then
        return stdnse.format_output(true, ("ERROR: %s"):format(r.reason))
      else
        break
      end
    end

    if ( r.response.status == 200 ) then
      local status, cookiearray = parseAuthentication(r.response)
      if ( status ) then
        local schemes = {}
        for id, cookie in ipairs(cookiearray) do
          if ( cookie ) then
		-- Create cookie entry not printable on first occurence
		if not ( cookie_table[cookie['name']]) then
		  cookie_table[cookie['name']] = { type={}, from={}, value= cookie['value'], vuln=false}
		end
      		    local urldata = urlhandler.parse(urlhandler.build(r.url), {scheme="", authority="", userinfo="", user="", password="", host="", port="", path="", params="", query="", fragment=""})
	       
	        -- Analysis of secureness based on OWASP specifications
		-- Secure Attribute
		if not ( cookie['secure'] ) then
                 cookie_table[cookie['name']]['type']['notSecure'] = ":secure flag not set"
                 cookie_table[cookie['name']]['vuln'] = true
                 cookie_table[cookie['name']]['from'][urldata['host']..urldata['path']] = true
		
	       end
	       -- httponly attribute
	       if not ( cookie['httponly'] ) then
                 cookie_table[cookie['name']]['type']['notHttpOnly'] = ":HttpOnly flag not set"
                 cookie_table[cookie['name']]['vuln'] = true
                 cookie_table[cookie['name']]['from'][urldata['host']..urldata['path']] = true
	       end
		-- Loose path attribute
	       if ( cookie['path'] ) then
		    -- Path must be enclosed in the same path as the url
		    local isClosed = false
		    if cookie['path'] == urldata['path'] then
			isClosed = true
		    end

		    if not ( isClosed) then
                 	cookie_table[cookie['name']]['type']['pathNotClosed'] = ("Cookie path is " .. cookie['path'])
                 	cookie_table[cookie['name']]['vuln'] = true
                 	cookie_table[cookie['name']]['from'][urldata['host']..urldata['path']] = true
		    	
		    end
	       end
		-- Loose domain attribute
		if cookie['domain'] then
			if not (cookie['domain'] == urldata['host']) then
				
                 		cookie_table[cookie['name']]['type']['domainNotClosed'] = ("Cookie domain is " .. cookie['domain'])
                 		cookie_table[cookie['name']]['vuln'] = true
                 		cookie_table[cookie['name']]['from'][urldata['host']..urldata['path']] = true
			end
		else
                 	cookie_table[cookie['name']]['type']['domainNotClosed'] = ("Cookie domain not specified")
                 	cookie_table[cookie['name']]['vuln'] = true
                 	cookie_table[cookie['name']]['from'][urldata['host']..urldata['path']] = true
		
		end
          end
        end
     end
     
     -- if 200
     end
  end
    -- Generate table
    for key, values in pairs(cookie_table) do
	if (values['vuln']) then
		print(values['type'])
	   local indexer = 0
	   local tempfrom = {}
	   for k,v in pairs(values['from']) do
		tempfrom[indexer] = k
		indexer = indexer+1
	   end
	   indexer = 0
	   for i, v in pairs(values['type']) do
		if (indexer == 0) then
	  		tab.addrow(auth_urls, key, i, v, tempfrom[indexer])
		else
			if (tempfrom[indexer]) then
	  			tab.addrow(auth_urls, "", i, v, tempfrom[indexer])
			else
	  			tab.addrow(auth_urls, "", i, v, "")
			end
		end
		indexer = indexer+1
	   end
	   while (tempfrom[indexer]) do	
		tab.addrow(auth_urls, "", "", "", tempfrom[indexer])
		indexer = indexer+1
	   end 
	end
	tab.addrow(auth_urls, "","","","")
    end

    local result = { tab.dump(auth_urls) }
    result.name = crawler:getLimitations()
    return stdnse.format_output(true, result)
end
