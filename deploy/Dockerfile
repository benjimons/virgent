# Always-on Virgent monitor as a container.
#   docker build -t virgent -f deploy/Dockerfile .
#   docker run -d --name virgent \
#     -e VIRGENT_AUDIT_KEY=... \
#     -v virgent-state:/var/lib/virgent \
#     -v /var/log:/host/var/log:ro \
#     virgent
#
# For host + runtime inspection of the *host* (not the container), run with
# --pid=host and mount the host filesystem read-only; otherwise it inspects
# the container itself. Response actions stay dry-run unless you wire an
# executor and grant approvals.
FROM python:3.12-slim

RUN useradd --system --create-home --home-dir /home/virgent virgent \
    && mkdir -p /var/lib/virgent && chown virgent:virgent /var/lib/virgent

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

USER virgent
ENV VIRGENT_WORKDIR=/var/lib/virgent
VOLUME ["/var/lib/virgent"]

# Continuous monitoring; override CMD to add --log sources for SOC detection.
ENTRYPOINT ["virgent", "--workdir", "/var/lib/virgent"]
CMD ["watch", "--interval", "60", "--log", "/host/var/log/auth.log"]
