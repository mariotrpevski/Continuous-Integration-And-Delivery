FROM nginx:alpine
COPY nginx.conf /etc/nginx/nginx.conf
COPY CIADProject/wwwroot/ /usr/share/nginx/html/