#!/bin/bash

# --- 项目配置 ---
CONTAINER_NAME="ais2api"
IMAGE_NAME="ellinalopez/cloud-studio:latest"
HOST_PORT="8889"
ENV_FILE="app.env" # 指定您的环境文件名

# --- 代理配置 ---
PROXY_URL=""

# -------------------------------------------------------------------

# 检查环境文件是否存在
if [ ! -f "$ENV_FILE" ]; then
    echo "错误: 环境文件 '$ENV_FILE' 不存在！"
    exit 1
fi

echo "===== 开始部署: $CONTAINER_NAME ====="

# 1. 拉取最新的 Docker 镜像
echo "--> 正在拉取最新镜像: $IMAGE_NAME..."
docker pull $IMAGE_NAME

# 2. 停止并删除同名的旧容器
echo "--> 正在停止并删除旧容器..."
docker stop $CONTAINER_NAME > /dev/null 2>&1
docker rm $CONTAINER_NAME > /dev/null 2>&1

# 3. 准备并运行新容器
echo "--> 正在启动新容器..."

# 使用数组来构建 docker run 命令的参数
declare -a DOCKER_OPTS
DOCKER_OPTS=(
    -d
    --name "$CONTAINER_NAME"
    -p "${HOST_PORT}:7860"
    --env-file "$ENV_FILE"
    --restart unless-stopped
)

# 条件性地向数组中添加挂载参数
if [ -d "./auth" ]; then
    echo "--> 检测到 'auth' 目录..."
    
    # [核心修正] 在挂载前，自动修正目录权限
    echo "--> 正在为 'auth' 目录设置权限..."
    sudo chown -R 1000:1000 ./auth
    
    echo "--> 正在将 'auth' 目录挂载到容器中..."
    DOCKER_OPTS+=(-v "$(pwd)/auth:/app/auth")
else
    echo "--> 未检测到 'auth' 目录，跳过挂载。"
fi

# 条件性地向数组中添加代理参数
if [ -n "$PROXY_URL" ]; then
    echo "--> 检测到代理配置，将为容器启用代理: $PROXY_URL"
    DOCKER_OPTS+=(-e "HTTP_PROXY=${PROXY_URL}")
    DOCKER_OPTS+=(-e "HTTPS_PROXY=${PROXY_URL}")
else
    echo "--> 未配置代理。"
fi

# 使用数组展开来执行命令，确保参数正确传递
docker run "${DOCKER_OPTS[@]}" "$IMAGE_NAME"


# 4. 检查容器状态
echo ""
echo "--> 检查容器状态 (等待几秒钟让容器启动):"
sleep 5
docker ps | grep $CONTAINER_NAME

echo ""
echo "===== 部署完成！====="
echo "服务应该正在运行在 http://<你的服务器IP>:${HOST_PORT}"
echo "您可以通过 'docker logs -f $CONTAINER_NAME' 查看实时日志。"