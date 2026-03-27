
## 🚀 Usage:

python

```python
# Start API server
from ubs_api_integration import UBSAPIServer

server = UBSAPIServer(host='0.0.0.0', port=8080)
server.start(blocking=True)
```




## 📋 API Endpoints:

```
GET  /              - API Info
GET  /health        - Health Check
POST /parse         - Parse UBS content
POST /convert       - Convert to format
POST /validate      - Validate UBS syntax
GET  /lookup        - Check if domain blocked
GET  /stats         - Get statistics
```


---
## 🚀 Start the API server:

python

```python
# In a separate terminal
python3 -c "
from ubs_api_integration import UBSAPIServer

server = UBSAPIServer(host='0.0.0.0', port=8080)
server.start(blocking=True)
"
```

Then you can test the API:

bash

```bash
# Health Check
curl http://localhost:8080/health

# Parse UBS content
curl -X POST http://localhost:8080/parse \
  -H "Content-Type: application/json" \
  -d '{"content": "malware.com :ttl=60"}'
```

## 📚 Available functionality:

### TTL Extension:

python

```python
from ubs_ttl_extension import UBSConverterTTL
- to_unbound_ttl()
- to_bind_ttl()
- to_dnsmasq_ttl()
- to_pihole_ttl()
- to_coredns_ttl()
- to_ttl_report()
```

### API Server:

```
GET  /health        - Server status
POST /parse         - Parse UBS
POST /convert       - Convert format
POST /validate      - Validate syntax
GET  /lookup        - Domain lookup
GET  /stats         - Statistics
```

----
