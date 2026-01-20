FROM nginx:alpine

# Copy nginx configurations
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY nginx-custom-ca.conf /etc/nginx/conf.d/default-custom-ca.conf

# Create SSL directory
RUN mkdir -p /etc/nginx/ssl

# Create log directory
RUN mkdir -p /var/log/nginx

# Create certbot webroot for ACME challenges
RUN mkdir -p /var/www/certbot

# Create entrypoint script to select config based on environment
RUN echo '#!/bin/sh' > /docker-entrypoint-custom.sh && \
    echo 'set -e' >> /docker-entrypoint-custom.sh && \
    echo 'if [ "$CUSTOM_CA" = "true" ]; then' >> /docker-entrypoint-custom.sh && \
    echo '  cp /etc/nginx/conf.d/default-custom-ca.conf /etc/nginx/conf.d/default.conf' >> /docker-entrypoint-custom.sh && \
    echo '  echo "✓ Using custom CA configuration"' >> /docker-entrypoint-custom.sh && \
    echo 'else' >> /docker-entrypoint-custom.sh && \
    echo '  echo "✓ Using default configuration"' >> /docker-entrypoint-custom.sh && \
    echo 'fi' >> /docker-entrypoint-custom.sh && \
    echo 'exec /docker-entrypoint.sh nginx -g "daemon off;"' >> /docker-entrypoint-custom.sh && \
    chmod +x /docker-entrypoint-custom.sh

# Expose ports
EXPOSE 80 443

# Use custom entrypoint that selects config, then calls nginx entrypoint
ENTRYPOINT ["/docker-entrypoint-custom.sh"]
