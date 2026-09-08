@echo off
if not exist clean_build_env mkdir clean_build_env
xcopy app clean_build_env\app\ /E /I /Y
rmdir /S /Q clean_build_env\app\storage
rmdir /S /Q clean_build_env\app\__pycache__
copy test_*.py clean_build_env\ /Y
copy tc*.py clean_build_env\ /Y
copy requirements.txt clean_build_env\ /Y
copy Dockerfile.test clean_build_env\Dockerfile /Y
cd clean_build_env
set DOCKER_BUILDKIT=0
docker build -t upce-test .
