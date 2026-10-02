# Imagen sandbox para wik3 — kali rolling + toolchain de pentest.
# Se tagea como `fabro-agent:latest` porque el provider docker de Fabro
# (v0.176) levanta ese tag de forma hardcoded.
#
# Build:
#   docker build -t fabro-agent:latest fabro/workflows/wik3/docker/

FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    PYTHONUNBUFFERED=1 \
    PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin

#
# Toolset minimo basado en telemetria real del workflow (corrida 01KPGVA78N):
# el agente usa curl ~90% del tiempo + nmap puntual + python3 para Playwright.
# Se removieron: whatweb, wafw00f, subfinder, amass, httpx-toolkit, nuclei,
# feroxbuster, nikto, sqlmap, seclists, wordlists, gitleaks, trufflehog,
# arjun, dalfox-py.
# Se mantienen ffuf/gobuster por ser livianos y utiles si el agente los elige.

# Doble `apt-get update` + retry: Kali rolling tiene mirrors a veces
# desincronizados con el index (típico error: 404 en .deb que el index
# referencia pero el package mirror todavía no tiene). Un segundo update
# fuerza el refresh; el retry da una pasada más por si el primer attempt
# pegó con un mirror parcialmente sincronizado.
RUN for i in 1 2 3; do \
        apt-get update \
        && apt-get update \
        && apt-get install -y --no-install-recommends \
            bash coreutils curl wget ca-certificates git jq \
            gnupg \
            dnsutils whois iputils-ping net-tools iproute2 \
            python3 python3-pip python3-venv \
            nmap \
            ffuf gobuster \
            file unzip xxd \
        && break || { echo "apt retry $i/3"; sleep 5; }; \
    done \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# yq (instalador binario, más confiable que el paquete apt en kali)
RUN ARCH=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/') \
    && curl -fsSL -o /usr/local/bin/yq \
        https://github.com/mikefarah/yq/releases/latest/download/yq_linux_${ARCH} \
    && chmod +x /usr/local/bin/yq

# `python` → `python3`: el agente a veces invoca `python` (no `python3`) en sus
# comandos ad-hoc; sin este symlink falla con `env: 'python': No such file or
# directory`. /usr/local/bin va primero en PATH, así no pisa venvs (que usan su
# propio bin) ni los CLIs symlinkeados.
RUN ln -sf /usr/bin/python3 /usr/local/bin/python \
    && python --version

# Python: requests + bs4 para probes web artesanales
RUN pip3 install --break-system-packages --no-cache-dir \
        requests beautifulsoup4

# jwt_tool
RUN cd /opt \
    && git clone --depth 1 https://github.com/ticarpi/jwt_tool.git \
    && pip3 install --break-system-packages --no-cache-dir pycryptodomex termcolor ratelimit \
    && ln -sf /opt/jwt_tool/jwt_tool.py /usr/local/bin/jwt_tool \
    && chmod +x /opt/jwt_tool/jwt_tool.py

# Playwright + Chromium para capturas de evidencia.
# `playwright install --with-deps` corre apt-get install internamente para
# los browser deps; le aplicamos el mismo retry-loop por mirror desync.
RUN pip3 install --break-system-packages --no-cache-dir playwright pillow \
    && for i in 1 2 3; do \
        apt-get update \
        && playwright install --with-deps chromium \
        && break || { echo "playwright retry $i/3"; sleep 5; }; \
    done \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# ─── Herramientas de "acupuntura" (pocas requests, alta senal) ───
#
# Go tools via toolchain temporal: instalamos golang-go, buildeamos las tools,
# las copiamos a /usr/local/bin, y desinstalamos Go para no inflar la imagen.

RUN for i in 1 2 3; do \
        apt-get update && apt-get install -y --no-install-recommends golang-go \
        && break || { echo "apt retry $i/3"; sleep 5; }; \
    done \
    && export PATH=/root/go/bin:$PATH GOPATH=/root/go \
    # sourcemapper: reconstruye source desde .js.map
    && go install github.com/denandz/sourcemapper@latest \
    # gau + waybackurls: URLs historicas (wayback, otx, commoncrawl) sin tocar al target
    && go install github.com/lc/gau/v2/cmd/gau@latest \
    && go install github.com/tomnomnom/waybackurls@latest \
    # tlsx: 1 handshake, todo el info de cert + SANs
    && go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest \
    # interactsh-client: callbacks OOB para blind vulns
    && go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest \
    && cp /root/go/bin/* /usr/local/bin/ \
    && apt-get remove -y golang-go \
    && apt-get autoremove -y \
    && apt-get clean \
    && rm -rf /root/go /root/.cache/go-build /var/lib/apt/lists/*

# LinkFinder + SecretFinder: extraen endpoints/secrets de bundles JS locales.
# SecretFinder.py importa `requests_file` (FileAdapter) y `lxml`; sin ellos el
# tool aborta con `ModuleNotFoundError: No module named 'requests_file'` en cada
# invocación. El import-check al final rompe el build si algún dep falta.
RUN pip3 install --break-system-packages --no-cache-dir jsbeautifier requests-file lxml \
    && cd /opt \
    && git clone --depth 1 https://github.com/GerbenJavado/LinkFinder.git \
    && ln -sf /opt/LinkFinder/linkfinder.py /usr/local/bin/linkfinder \
    && chmod +x /opt/LinkFinder/linkfinder.py \
    && git clone --depth 1 https://github.com/m4ll0k/SecretFinder.git \
    && ln -sf /opt/SecretFinder/SecretFinder.py /usr/local/bin/secretfinder \
    && chmod +x /opt/SecretFinder/SecretFinder.py \
    && python3 -c "import requests_file, jsbeautifier, lxml"

# SAST / analisis estatico de JS/TS
# Semgrep: pattern-based SAST con 2000+ rulesets (p/javascript, p/typescript, p/owasp-top-ten).
# Se instala en un venv AISLADO: semgrep necesita pydantic>=2.5 (importa
# pydantic.Discriminator), pero varias tools cloud que se instalan después en el
# system Python con --break-system-packages (prowler/checkov/azure-cli/...) le
# downgradean pydantic y lo rompen en runtime con
# `ImportError: cannot import name 'Discriminator' from 'pydantic'`. El venv lo blinda.
RUN python3 -m venv /opt/semgrep-venv \
    && /opt/semgrep-venv/bin/pip install --upgrade pip \
    && /opt/semgrep-venv/bin/pip install --no-cache-dir semgrep \
    && ln -sf /opt/semgrep-venv/bin/semgrep /usr/local/bin/semgrep \
    && semgrep --version

# retire.js: matchea bundles JS contra CVE DB de libs conocidas (jQuery vuln, lodash, etc.).
# `retire --version` verifica el install ANTES de remover npm: si el install falla, el build
# debe romper. Antes el `npm install ... | tail -5` se tragaba el exit code de npm (sh -c no
# tiene pipefail), así que un install fallido pasaba silencioso y la imagen salía sin retire
# → `retire: command not found` en runtime. retire corre con node (no npm), así que es seguro
# remover npm una vez verificado.
RUN for i in 1 2 3; do \
        apt-get update \
        && apt-get install -y --no-install-recommends nodejs npm \
        && break || { echo "apt retry $i/3"; sleep 5; }; \
    done \
    && npm install -g --no-fund --no-audit retire \
    && retire --version \
    && apt-get remove -y npm \
    && apt-get autoremove -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /root/.npm

# GraphQL surgical tools (GitHub-only, no PyPI).
# graphw00f: sin requirements.txt, deps minimas inline.
# graphql-cop: si tiene requirements.txt.
RUN pip3 install --break-system-packages --no-cache-dir requests termcolor urllib3 \
    && cd /opt \
    && git clone --depth 1 https://github.com/dolevf/graphw00f.git \
    && printf '#!/bin/sh\ncd /opt/graphw00f && exec python3 main.py "$@"\n' > /usr/local/bin/graphw00f \
    && chmod +x /usr/local/bin/graphw00f \
    && git clone --depth 1 https://github.com/dolevf/graphql-cop.git \
    && pip3 install --break-system-packages --no-cache-dir -r graphql-cop/requirements.txt \
    && printf '#!/bin/sh\ncd /opt/graphql-cop && exec python3 graphql-cop.py "$@"\n' > /usr/local/bin/graphql-cop \
    && chmod +x /usr/local/bin/graphql-cop

# Hurl: build from source via cargo.
# El .deb precompilado fue linkeado contra libxml2.so.2 (ABI vieja) y kali
# rolling no tiene ese runtime. Compilar desde fuente evita el mismatch.
# La toolchain de rust se remueve al final para no inflar la imagen (~600 MB
# temporales que bajan a ~12 MB final del binario hurl).
#
# Versión pineada: hurl 8.x requiere rustc 1.95+ pero el `cargo` de kali
# rolling al momento del build trae 1.92.0 (sept 2025). hurl 7.1.0 es la
# última release que soporta rustc 1.91.1, así que es compatible. Cuando
# kali avance el cargo, se puede deshacer el pin (o pinear a la última
# que pegue con la versión nueva).
RUN for i in 1 2 3; do \
        apt-get update \
        && apt-get install -y --no-install-recommends \
            cargo rustc pkg-config libxml2-dev libssl-dev libclang-dev clang \
        && break || { echo "apt retry $i/3"; sleep 5; }; \
    done \
    && cargo install hurl --version 7.1.0 --root /usr/local \
    && apt-get remove -y cargo rustc libxml2-dev libssl-dev pkg-config libclang-dev clang \
    && apt-get autoremove -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /root/.cargo /root/.rustup /tmp/* \
    && hurl --version

# ─── Mobile pentest toolchain (Android + iOS best-effort) ──────────────────
#
# Cubre los flujos típicos sin device físico:
#   - Android: decompile/disassemble (apktool/jadx/dex2jar/cfr/procyon),
#     static analysis (androguard, mobsfscan, apkleaks, apkid, qark),
#     runtime instrumentation prep (frida-tools, objection, fridump).
#   - iOS (best-effort sin macOS): análisis binario Mach-O via radare2,
#     parsing de plist via plistutil, libimobiledevice para devices
#     conectados por USB-forwarding. NO incluye Mac-only tools
#     (theos, class-dump full, bagbak).
#
# Para análisis dinámico con device físico (Android emulator o iOS
# jailbroken con frida-server), el operador conecta el device por USB
# al host del operador y ssh-forward al sandbox. El sandbox aporta los
# clientes (frida CLI, objection); el server vive en el device.

# Java runtime: requerido por apktool, jadx, dex2jar, cfr, bundletool,
# apksigner. Headless porque no necesitamos GUI.
# Mismo retry-loop que el primer apt install (mirror desync en Kali rolling).
RUN for i in 1 2 3; do \
        apt-get update \
        && apt-get update \
        && apt-get install -y --no-install-recommends \
            openjdk-21-jre-headless \
            libimobiledevice-utils libplist-utils \
            radare2 yara \
            apksigner aapt zipalign \
        && break || { echo "apt retry $i/3"; sleep 5; }; \
    done \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Versiones pineadas para reproducibilidad y evitar rate-limit de
# api.github.com (60 req/h sin token). Bumpear manualmente cada release.
ARG APKTOOL_VERSION=3.0.2
ARG JADX_VERSION=1.5.1
ARG D2J_VERSION=2.4
ARG CFR_VERSION=0.152
ARG BUNDLETOOL_VERSION=1.18.1
ARG TRUFFLEHOG_VERSION=3.84.2
ARG GITLEAKS_VERSION=8.21.2

# apktool — decompile APK to smali + resources. El asset oficial se
# llama `apktool_<version>.jar` (no `apktool.jar`), por eso usamos
# version pinned + URL explícita.
RUN curl -fsSL -o /opt/apktool.jar \
        "https://github.com/iBotPeaches/Apktool/releases/download/v${APKTOOL_VERSION}/apktool_${APKTOOL_VERSION}.jar" \
    && printf '#!/bin/sh\nexec java -jar /opt/apktool.jar "$@"\n' > /usr/local/bin/apktool \
    && chmod +x /usr/local/bin/apktool /opt/apktool.jar \
    && apktool --version

# jadx — DEX/APK to Java decompiler. CLI + GUI en el mismo zip.
RUN cd /opt \
    && curl -fsSL -o jadx.zip \
        "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" \
    && unzip -q jadx.zip -d jadx \
    && rm jadx.zip \
    && ln -sf /opt/jadx/bin/jadx /usr/local/bin/jadx \
    && ln -sf /opt/jadx/bin/jadx-gui /usr/local/bin/jadx-gui \
    && jadx --version

# dex2jar — DEX → JAR conversion (input alt para decompiladores Java).
RUN cd /opt \
    && curl -fsSL -o dex2jar.zip \
        "https://github.com/pxb1988/dex2jar/releases/download/v${D2J_VERSION}/dex-tools-v${D2J_VERSION}.zip" \
    && unzip -q dex2jar.zip \
    && rm dex2jar.zip \
    && mv dex-tools-v${D2J_VERSION} dex2jar \
    && chmod +x /opt/dex2jar/*.sh \
    && ln -sf /opt/dex2jar/d2j-dex2jar.sh /usr/local/bin/d2j-dex2jar \
    && ln -sf /opt/dex2jar/d2j-jar2dex.sh /usr/local/bin/d2j-jar2dex

# CFR — Java decompiler alternativo (single JAR ~3 MB).
RUN curl -fsSL -o /opt/cfr.jar \
        "https://github.com/leibnitz27/cfr/releases/download/${CFR_VERSION}/cfr-${CFR_VERSION}.jar" \
    && printf '#!/bin/sh\nexec java -jar /opt/cfr.jar "$@"\n' > /usr/local/bin/cfr \
    && chmod +x /usr/local/bin/cfr

# bundletool — extract APKs/info from AAB (Android App Bundle).
RUN curl -fsSL -o /opt/bundletool.jar \
        "https://github.com/google/bundletool/releases/download/${BUNDLETOOL_VERSION}/bundletool-all-${BUNDLETOOL_VERSION}.jar" \
    && printf '#!/bin/sh\nexec java -jar /opt/bundletool.jar "$@"\n' > /usr/local/bin/bundletool \
    && chmod +x /usr/local/bin/bundletool

# Python stack — core estable (todo lo critical en un solo RUN).
#   androguard   - lib + CLI multi-tool para APK analysis.
#   mobsfscan    - MobSF static rules como CLI.
#   apkleaks     - regex secrets scanning en APKs.
#   apkid        - identifica obfuscators/packers via yara.
#   frida-tools  - CLI clients (frida, frida-ps, frida-trace).
#   objection    - frida wrapper para runtime exploration.
#   r2pipe       - python bindings de radare2 (para scripting).
RUN pip3 install --break-system-packages --no-cache-dir \
        androguard mobsfscan apkleaks apkid \
        frida-tools objection r2pipe \
    && frida --version \
    && objection --version 2>&1 | head -1 \
    && androguard --help 2>&1 | head -1 || true

# Python stack — opcionales (pueden fallar sin romper el build).
#   qark         - Quick Android Review Kit. A veces tiene issues con
#                  Python 3.12+ por dependencies viejas.
#   trueseeing   - SAST/DAST para Android.
RUN pip3 install --break-system-packages --no-cache-dir qark || \
    echo "WARN: qark install failed (probably Python compat); continuing" >&2
RUN pip3 install --break-system-packages --no-cache-dir trueseeing || \
    echo "WARN: trueseeing install failed; continuing" >&2

# fridump — dump memory de procesos via frida (no tiene PyPI).
RUN cd /opt \
    && git clone --depth 1 https://github.com/Nightbringer21/fridump.git \
    && printf '#!/bin/sh\nexec python3 /opt/fridump/fridump.py "$@"\n' > /usr/local/bin/fridump \
    && chmod +x /usr/local/bin/fridump

# Secrets scanning: trufflehog + gitleaks. Útiles para dumps de
# bundles JS, APKs decompilados, repos.
RUN ARCH=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/') \
    && curl -fsSL -o /tmp/trufflehog.tgz \
        "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_${ARCH}.tar.gz" \
    && tar xzf /tmp/trufflehog.tgz -C /usr/local/bin/ trufflehog \
    && rm /tmp/trufflehog.tgz \
    && trufflehog --version 2>&1 | head -1

RUN ARCH=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/') \
    && GL_ARCH=$(echo $ARCH | sed 's/amd64/x64/') \
    && curl -fsSL -o /tmp/gitleaks.tgz \
        "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${GL_ARCH}.tar.gz" \
    && tar xzf /tmp/gitleaks.tgz -C /usr/local/bin/ gitleaks \
    && rm /tmp/gitleaks.tgz \
    && gitleaks version

# ─── Cloud pentest toolchain (AWS + GCP + Azure + K8s + IaC) ───────────────
#
# Cubre auditoría de cuentas cloud autenticadas (el operador provee creds)
# y enumeración de superficie expuesta:
#   - CLIs nativas para los 3 providers (aws-cli, gcloud, az).
#   - Multi-cloud audit/CSPM (prowler, scoutsuite).
#   - IAM analysis específico AWS (cloudsplaining, parliament, policy_sentry).
#   - AWS exploitation (pacu).
#   - Kubernetes (kubectl, kube-bench, kubescape, kubeaudit, popeye).
#   - IaC scanning (trivy, checkov, kics).
#   - Container/image scanning (trivy, grype, syft).
#   - Terraform CLI para parsear/comprobar setup.

ARG TERRAFORM_VERSION=1.13.4
ARG KUBECTL_VERSION=1.32.1
ARG KUBE_BENCH_VERSION=0.13.0
ARG KUBESCAPE_VERSION=3.0.34
ARG TRIVY_VERSION=0.70.0
ARG GRYPE_VERSION=0.85.0
ARG SYFT_VERSION=1.18.0
ARG KICS_VERSION=2.1.20

# AWS CLI v2 — bundle oficial (no via pip, que da v1 y está deprecado).
RUN ARCH=$(uname -m | sed 's/aarch64/arm64/; s/x86_64/x86_64/') \
    && curl -fsSL -o /tmp/awscliv2.zip \
        "https://awscli.amazonaws.com/awscli-exe-linux-${ARCH}.zip" \
    && unzip -q /tmp/awscliv2.zip -d /tmp \
    && /tmp/aws/install \
    && rm -rf /tmp/awscliv2.zip /tmp/aws \
    && aws --version

# Google Cloud SDK — vía apt repo oficial. Incluye gcloud + gsutil + bq.
RUN curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg \
        | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" \
        > /etc/apt/sources.list.d/google-cloud-sdk.list \
    && for i in 1 2 3; do \
        apt-get update \
        && apt-get install -y --no-install-recommends google-cloud-cli \
        && break || { echo "apt retry $i/3"; sleep 5; }; \
    done \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && gcloud --version 2>&1 | head -3

# Azure CLI — via pip. El apt repo de Microsoft solo soporta Ubuntu LTS
# codenames específicos, así que pip es más portable para kali rolling.
RUN pip3 install --break-system-packages --no-cache-dir azure-cli \
    && az --version 2>&1 | head -1

# kubectl — Kubernetes CLI.
RUN ARCH=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/') \
    && curl -fsSL -o /usr/local/bin/kubectl \
        "https://dl.k8s.io/release/v${KUBECTL_VERSION}/bin/linux/${ARCH}/kubectl" \
    && chmod +x /usr/local/bin/kubectl \
    && kubectl version --client 2>&1 | head -1

# Terraform — Hashicorp binary release.
RUN ARCH=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/') \
    && curl -fsSL -o /tmp/tf.zip \
        "https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_${ARCH}.zip" \
    && unzip -q /tmp/tf.zip -d /usr/local/bin/ \
    && rm /tmp/tf.zip \
    && terraform --version 2>&1 | head -1

# Trivy — vulnerability scanner para containers + IaC + filesystem.
RUN ARCH=$(uname -m | sed 's/x86_64/64bit/; s/aarch64/ARM64/') \
    && curl -fsSL -o /tmp/trivy.tgz \
        "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${ARCH}.tar.gz" \
    && tar xzf /tmp/trivy.tgz -C /usr/local/bin/ trivy \
    && rm /tmp/trivy.tgz \
    && trivy --version 2>&1 | head -1

# Grype — vulnerability scanner alternativo (Anchore).
RUN curl -fsSL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
        | sh -s -- -b /usr/local/bin v${GRYPE_VERSION} \
    && grype version 2>&1 | head -3

# Syft — SBOM generation (input alt para Grype y otros).
RUN curl -fsSL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
        | sh -s -- -b /usr/local/bin v${SYFT_VERSION} \
    && syft version 2>&1 | head -3

# Kubernetes audit: kube-bench (CIS), kubescape, kubeaudit, popeye.
RUN ARCH=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/') \
    && curl -fsSL -o /tmp/kube-bench.tgz \
        "https://github.com/aquasecurity/kube-bench/releases/download/v${KUBE_BENCH_VERSION}/kube-bench_${KUBE_BENCH_VERSION}_linux_${ARCH}.tar.gz" \
    && tar xzf /tmp/kube-bench.tgz -C /usr/local/bin/ kube-bench \
    && rm /tmp/kube-bench.tgz \
    && kube-bench version 2>&1 | head -1

RUN ARCH=$(uname -m | sed 's/x86_64/x86_64/; s/aarch64/arm64/') \
    && curl -fsSL -o /usr/local/bin/kubescape \
        "https://github.com/kubescape/kubescape/releases/download/v${KUBESCAPE_VERSION}/kubescape-ubuntu-latest" \
    && chmod +x /usr/local/bin/kubescape \
    && kubescape version 2>&1 | head -1

# KICS — IaC security scanner (Checkmarx).
RUN ARCH=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/') \
    && curl -fsSL -o /tmp/kics.tgz \
        "https://github.com/Checkmarx/kics/releases/download/v${KICS_VERSION}/kics_${KICS_VERSION}_linux_${ARCH}.tar.gz" \
    && mkdir -p /opt/kics \
    && tar xzf /tmp/kics.tgz -C /opt/kics \
    && rm /tmp/kics.tgz \
    && ln -sf /opt/kics/kics /usr/local/bin/kics \
    && kics version 2>&1 | head -1 || true

# Python cloud security stack:
#   prowler         - multi-cloud audit (AWS/GCP/Azure/K8s/M365).
#   scoutsuite      - multi-cloud security auditing.
#   cloudsplaining  - AWS IAM least-privilege analysis.
#   pmapper         - AWS IAM graph: rutas de escalada de privilegios (abajo).
#   policy_sentry   - AWS IAM policy builder (least-privilege gen).
#   parliament      - AWS IAM policy linter.
#   pacu            - AWS exploitation framework.
#   checkov         - IaC security scanner (Terraform/CloudFormation/k8s).
#   cloudmapper     - AWS account visualizer / audit.
#   gcp_scanner     - GCP security scanner.
RUN pip3 install --break-system-packages --no-cache-dir \
        prowler scoutsuite cloudsplaining policy_sentry parliament \
        checkov \
    && prowler --version 2>&1 | head -1 \
    && scout --help 2>&1 | head -1 \
    && cloudsplaining --version 2>&1 | head -1

# Pacu — AWS exploitation framework. A veces tiene conflicts con prowler
# por boto3 versions; lo instalamos aparte con `|| true`.
RUN pip3 install --break-system-packages --no-cache-dir pacu \
    || echo "WARN: pacu install conflicts (boto3 versions); continuing"

# CloudMapper — AWS visualizer. Solo si no rompe el resto.
RUN pip3 install --break-system-packages --no-cache-dir cloudmapper \
    || echo "WARN: cloudmapper install failed; continuing"

# GCP scanner (Google's own tool).
RUN pip3 install --break-system-packages --no-cache-dir gcp_scanner \
    || echo "WARN: gcp_scanner install failed; continuing"

# s3-account-search — descubre S3 buckets de un AWS account.
RUN pip3 install --break-system-packages --no-cache-dir s3-account-search \
    || echo "WARN: s3-account-search install failed; continuing"

# PMapper (Principal Mapper) — construye un GRAFO de IAM y encuentra rutas de
# escalada de privilegios / accesos transitivos entre principals (complementa a
# cloudsplaining, que es por-policy). CLI: pmapper. Boto3 deps → install aparte.
RUN pip3 install --break-system-packages --no-cache-dir principalmapper \
    || echo "WARN: principalmapper (pmapper) install failed; continuing"

# Restaurar AWS CLI v2 al final: prowler/cloudmapper/etc instalan awscli
# v1 como dep transitiva via pip y sobreescriben /usr/local/bin/aws.
# Forzamos el symlink al binario v2 que el oficial installer dejó en
# /usr/local/aws-cli/v2/current/bin/aws.
RUN ln -sf /usr/local/aws-cli/v2/current/bin/aws /usr/local/bin/aws \
    && ln -sf /usr/local/aws-cli/v2/current/bin/aws_completer /usr/local/bin/aws_completer \
    && aws --version

# ─── Internal pentest toolchain (AD / SMB / Kerberos / MITM / pivot) ──────
#
# Cubre engagements de red interna típicos: enumeración Active Directory,
# autenticación SMB/Kerberos, lateral movement, MITM en red local,
# pivoting a través de VPN del cliente.
#
# Asunción: el operador conecta la wik3 a la red interna del cliente por
# medio de un túnel (VPN, reverse SSH, ligolo-agent). El agente fabro
# corre dentro del container con visibilidad de esa red.

ARG KERBRUTE_VERSION=1.0.3
ARG CHISEL_VERSION=1.10.1
ARG LIGOLO_VERSION=0.7.5

# Apt packages: SMB/LDAP/Kerberos clients, krb5 client, password crackers,
# network discovery, packet capture, etc.
# python3-venv: ensurepip para venvs aislados (netexec/certipy/etc usan
# venvs propios por conflicto de impacket versions).
RUN for i in 1 2 3; do \
        apt-get update \
        && apt-get update \
        && apt-get install -y --no-install-recommends \
            python3-venv python3-dev build-essential \
            smbclient cifs-utils \
            ldap-utils \
            krb5-user libkrb5-3 \
            arp-scan netdiscover fping masscan \
            tshark \
            responder \
            john hashcat \
            enum4linux \
            proxychains4 socat ncat netcat-openbsd \
            sshpass sshuttle \
            iproute2 iptables \
        && break || { echo "apt retry $i/3"; sleep 5; }; \
    done \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Python stack — varios paquetes AD/SMB/Kerberos tienen conflictos de
# versiones entre sí (típicamente sobre `impacket`: netexec requiere
# >=0.13, coercer/petitpotam requieren <0.11). Resolvemos con venvs
# aislados por herramienta — cada uno trae su propio impacket y los
# CLIs quedan en PATH via symlinks a /usr/local/bin.

# Core (no conflicto): ldapdomaindump, pywerview, adidnsdump.
# Estos sí están en PyPI estable.
RUN pip3 install --break-system-packages --no-cache-dir \
        ldapdomaindump pywerview adidnsdump \
    && ldapdomaindump --help 2>&1 | head -1 || true

# impacket en system Python (versión más estable para el agente).
RUN pip3 install --break-system-packages --no-cache-dir 'impacket<0.13' \
    && impacket-secretsdump 2>&1 | head -1 || true

# Rust toolchain — `aardwolf` (dep transitiva de NetExec) compila una extensión
# nativa y necesita cargo/rustc; sin esto el wheel de aardwolf falla y tumba el
# install de NetExec (root cause del build roto, jun 2026).
RUN apt-get update && apt-get install -y --no-install-recommends rustc cargo \
    && rm -rf /var/lib/apt/lists/* && rustc --version

# netexec en venv aislado. Install desde GitHub PINEADO a un release estable:
# `main` empezó a romper el wheel de su dependencia `aardwolf` y tumbaba TODO el
# build de la imagen. El `|| echo WARN` lo vuelve no-fatal (red de seguridad: si
# un upstream se rompe, el resto de la imagen igual se construye).
ARG NETEXEC_VERSION=v1.5.1
RUN python3 -m venv /opt/netexec-venv \
    && /opt/netexec-venv/bin/pip install --upgrade pip \
    && /opt/netexec-venv/bin/pip install --no-cache-dir \
        "git+https://github.com/Pennyw0rth/NetExec.git@${NETEXEC_VERSION}" \
    && ln -sf /opt/netexec-venv/bin/nxc /usr/local/bin/nxc \
    && ln -sf /opt/netexec-venv/bin/netexec /usr/local/bin/netexec \
    && nxc --version 2>&1 | head -1 \
    || echo "WARN: netexec install failed; continuing"

# certipy-ad en venv aislado (su impacket pin puede chocar con base).
RUN python3 -m venv /opt/certipy-venv \
    && /opt/certipy-venv/bin/pip install --upgrade pip \
    && /opt/certipy-venv/bin/pip install --no-cache-dir certipy-ad \
    && ln -sf /opt/certipy-venv/bin/certipy /usr/local/bin/certipy \
    && certipy --version 2>&1 | head -1

# bloodhound-python en venv aislado.
RUN python3 -m venv /opt/bloodhound-venv \
    && /opt/bloodhound-venv/bin/pip install --upgrade pip \
    && /opt/bloodhound-venv/bin/pip install --no-cache-dir bloodhound \
    && ln -sf /opt/bloodhound-venv/bin/bloodhound-python /usr/local/bin/bloodhound-python \
    && bloodhound-python --help 2>&1 | head -1 || true

# coercer + mitm6 en venv compartido (ambos SÍ están en PyPI).
RUN python3 -m venv /opt/coercer-venv \
    && /opt/coercer-venv/bin/pip install --upgrade pip \
    && /opt/coercer-venv/bin/pip install --no-cache-dir coercer mitm6 \
    && ln -sf /opt/coercer-venv/bin/coercer /usr/local/bin/coercer \
    && ln -sf /opt/coercer-venv/bin/mitm6 /usr/local/bin/mitm6 \
    && coercer --help 2>&1 | head -1 \
    && mitm6 --help 2>&1 | head -1

# enum4linux-ng — NO está en PyPI con ese nombre. Install desde GitHub.
RUN python3 -m venv /opt/enum4linux-ng-venv \
    && /opt/enum4linux-ng-venv/bin/pip install --upgrade pip \
    && /opt/enum4linux-ng-venv/bin/pip install --no-cache-dir \
        git+https://github.com/cddmp/enum4linux-ng.git \
    && ln -sf /opt/enum4linux-ng-venv/bin/enum4linux-ng /usr/local/bin/enum4linux-ng \
    && enum4linux-ng --help 2>&1 | head -1

# windapsearch (de ropnop, no en PyPI directo — repo Python).
RUN cd /opt \
    && git clone --depth 1 https://github.com/ropnop/windapsearch.git \
    && ln -sf /opt/windapsearch/windapsearch.py /usr/local/bin/windapsearch \
    && chmod +x /opt/windapsearch/windapsearch.py

# kerbrute — bruteforce/enumeration de usernames + password spray Kerberos.
# Binario único Go, no necesita compilar.
RUN ARCH=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/') \
    && curl -fsSL -o /usr/local/bin/kerbrute \
        "https://github.com/ropnop/kerbrute/releases/download/v${KERBRUTE_VERSION}/kerbrute_linux_${ARCH}" \
    && chmod +x /usr/local/bin/kerbrute \
    && kerbrute version 2>&1 | head -1

# chisel — TCP/UDP tunnel sobre HTTP. Útil para pivot.
RUN ARCH=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/') \
    && curl -fsSL -o /tmp/chisel.gz \
        "https://github.com/jpillora/chisel/releases/download/v${CHISEL_VERSION}/chisel_${CHISEL_VERSION}_linux_${ARCH}.gz" \
    && gunzip /tmp/chisel.gz \
    && mv /tmp/chisel /usr/local/bin/chisel \
    && chmod +x /usr/local/bin/chisel \
    && chisel --version 2>&1 | head -1

# ligolo-ng — pivoting moderno con TUN interface (preferible sobre chisel
# para tráfico que no es HTTP).
RUN ARCH=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/') \
    && curl -fsSL -o /tmp/ligolo-proxy.tgz \
        "https://github.com/Nicocha30/ligolo-ng/releases/download/v${LIGOLO_VERSION}/ligolo-ng_proxy_${LIGOLO_VERSION}_linux_${ARCH}.tar.gz" \
    && curl -fsSL -o /tmp/ligolo-agent.tgz \
        "https://github.com/Nicocha30/ligolo-ng/releases/download/v${LIGOLO_VERSION}/ligolo-ng_agent_${LIGOLO_VERSION}_linux_${ARCH}.tar.gz" \
    && mkdir -p /opt/ligolo \
    && tar xzf /tmp/ligolo-proxy.tgz -C /opt/ligolo proxy \
    && tar xzf /tmp/ligolo-agent.tgz -C /opt/ligolo agent \
    && ln -sf /opt/ligolo/proxy /usr/local/bin/ligolo-proxy \
    && ln -sf /opt/ligolo/agent /usr/local/bin/ligolo-agent \
    && rm -f /tmp/ligolo-*.tgz \
    && chmod +x /opt/ligolo/proxy /opt/ligolo/agent

# Re-asegurar semgrep del venv aislado AL FINAL (mismo patrón que aws-cli v2):
# mobsfscan (sección mobile) declara `semgrep` como dependencia y lo reinstala en
# el system Python, sobreescribiendo /usr/local/bin/{semgrep,pysemgrep} con
# entry-points que usan el pydantic (roto) del sistema. Además el launcher
# `semgrep` resuelve `pysemgrep` por PATH, así que hay que apuntar AMBOS al venv
# para que toda la cadena use el pydantic>=2.5 aislado. Sin esto: ImportError /
# traceback en cada `semgrep` (visto en runtime aunque el build pasaba).
RUN ln -sf /opt/semgrep-venv/bin/semgrep   /usr/local/bin/semgrep \
    && ln -sf /opt/semgrep-venv/bin/pysemgrep /usr/local/bin/pysemgrep \
    && semgrep --version

WORKDIR /workspace

# Entrypoint: instala extra CA cert (Burp Suite) si está montado en
# /etc/wik3-burp/ca.crt vía workflow.toml extra_mounts.
COPY wik3-entrypoint.sh /usr/local/bin/wik3-entrypoint.sh
RUN chmod +x /usr/local/bin/wik3-entrypoint.sh
ENTRYPOINT ["/usr/local/bin/wik3-entrypoint.sh"]
CMD ["bash"]
