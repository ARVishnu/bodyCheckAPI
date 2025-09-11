# Fast API Commands
python3 -m venv venv
source ./venv/bin/activate

uvicorn main:app --host 0.0.0.0 --port 8080 --reload

ngrok http 8080

cd "/Users/enestmac/Desktop/Vishnu Workspace/BodyCheckOfficial/BodyCheck/BodyCheck_Backend_CSV"
./venv/bin/python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload > backend_uvicorn.log 2>&1 &
curl -s http://127.0.0.1:8000/health




cloudflared tunnel --url http://localhost:8000
