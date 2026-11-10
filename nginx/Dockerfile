FROM nginx:1.27-alpine
COPY --chmod=755 crl-watch.sh /docker-entrypoint.d/90-crl-watch.sh
COPY templates/ /etc/nginx/templates/
# Remove the default site so only our listeners exist.
RUN rm -f /etc/nginx/conf.d/default.conf
ENV NGINX_ENVSUBST_FILTER=PROXY_
EXPOSE 8443 9443
