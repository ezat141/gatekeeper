-- GateKeeper rate limit: a token bucket and a daily quota for one identity, checked and spent
-- atomically. The M5 design, section 6.
--
-- KEYS[1]  bucket hash: tokens, ts
-- KEYS[2]  quota hash:  day, count
-- ARGV[1]  requests per second (refill rate)
-- ARGV[2]  burst (bucket capacity)
-- ARGV[3]  daily quota
-- ARGV[4]  now, in seconds since the epoch; empty in production, so Redis's clock is used and
--          every gateway instance shares one clock
--
-- Returns six integers: allowed (1/0), reason (0 none, 1 rate, 2 quota), tokens remaining,
-- quota remaining, retry-after seconds, seconds until the quota resets.

local rate = tonumber(ARGV[1])
local burst = tonumber(ARGV[2])
local quota = tonumber(ARGV[3])
local now = tonumber(ARGV[4])
if not now then
  local time = redis.call('TIME')
  now = tonumber(time[1]) + tonumber(time[2]) / 1000000
end

local day = math.floor(now / 86400)
local until_midnight = math.ceil((day + 1) * 86400 - now)

local tokens = burst
local stored_tokens = tonumber(redis.call('HGET', KEYS[1], 'tokens'))
local stored_ts = tonumber(redis.call('HGET', KEYS[1], 'ts'))
if stored_tokens and stored_ts then
  tokens = math.min(burst, stored_tokens + math.max(0, now - stored_ts) * rate)
end

local count = 0
if tonumber(redis.call('HGET', KEYS[2], 'day')) == day then
  count = tonumber(redis.call('HGET', KEYS[2], 'count')) or 0
end

-- Bucket first: a request refused for speed spends none of the day, and nothing is written.
if tokens < 1 then
  -- With integer rates of at least 1 (the configuration's minimum) this is always 1; the
  -- formula matters only for fractional rates.
  return {0, 1, 0, math.max(0, quota - count), math.max(1, math.ceil((1 - tokens) / rate)), until_midnight}
end

-- Then the quota: a request refused for the day takes no token, and nothing is written.
if count + 1 > quota then
  return {0, 2, math.floor(tokens), 0, math.max(1, until_midnight), until_midnight}
end

tokens = tokens - 1
count = count + 1
redis.call('HSET', KEYS[1], 'tokens', string.format('%.6f', tokens), 'ts', string.format('%.6f', now))
redis.call('EXPIRE', KEYS[1], math.max(1, math.ceil(burst / rate * 2)))
redis.call('HSET', KEYS[2], 'day', string.format('%d', day), 'count', string.format('%d', count))
redis.call('EXPIREAT', KEYS[2], string.format('%d', (day + 1) * 86400 + 3600))
return {1, 0, math.floor(tokens), quota - count, 0, until_midnight}
