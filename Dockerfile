FROM python:3-alpine
COPY ./requirements.txt /requirements.txt
RUN python3 -m pip install -r /requirements.txt -i https://mirrors.tuna.tsinghua.edu.cn/pypi/web/simple
COPY ./ /app
WORKDIR /app
RUN chmod +x /app/entrypoint.sh
ENTRYPOINT ["./entrypoint.sh"]