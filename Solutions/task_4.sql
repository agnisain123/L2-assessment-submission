-- Query 1: Find the hour of the day with the highest average response time
SELECT 
    strftime('%H', timestamp) AS hour_of_day,
    AVG(response_time_ms) AS avg_response_time
FROM 
    request_logs
GROUP BY 
    hour_of_day
ORDER BY 
    avg_response_time DESC
LIMIT 1;

-- Query 2: Identify any IPs that sent more than 350 requests with a 429 status code
SELECT 
    ip_address, 
    COUNT(*) AS request_count
FROM 
    request_logs
WHERE 
    status_code = 429
GROUP BY 
    ip_address
HAVING 
    COUNT(*) > 350;

-- Query 3: Calculate the total bytes sent for requests where response time > 500ms
SELECT 
    SUM(bytes_sent) AS total_bytes_sent
FROM 
    request_logs
WHERE 
    response_time_ms > 500;
