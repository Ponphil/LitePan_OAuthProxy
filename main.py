import uvicorn
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from server import router, oauth_proxy
import os
import sys
from dotenv import load_dotenv  # 需要添加到requirements.txt

# 加载环境变量
load_dotenv()

current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

app = FastAPI(
    title="OAuth代理服务器",
    description="为网盘OAuth认证提供代理服务",
    version="1.0.0"
)

# 添加CORS中间件
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 挂载静态文件
if os.path.exists("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")

# 注册路由
app.include_router(router)

@app.on_event("startup")
async def startup_event():
    """启动时初始化"""
    await oauth_proxy.start_cleanup_task()
    print("="*50)
    print("🚀 OAuth代理服务器启动成功！")
    external_url = os.getenv('EXTERNAL_URL', 'http://localhost:8080')
    print(f"📱 网页界面: {external_url}/oauth")
    print(f"🔗 API文档: {external_url}/docs")
    print("="*50)

if __name__ == "__main__":
    port = int(os.getenv('INTERNAL_PORT', 5288))
    print(f"🔧 调试信息: INTERNAL_PORT={os.getenv('INTERNAL_PORT')}, 实际端口={port}")
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=port,
        reload=True,
        log_level="info"
    )