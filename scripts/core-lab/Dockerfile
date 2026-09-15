FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      iproute2 ethtool nftables procps bash mount util-linux iputils-ping \
      autoconf automake libtool pkg-config gcc make libev-dev \
      tk xvfb imagemagick x11-apps xauth fonts-dejavu git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 https://github.com/coreemu/core.git /opt/core
WORKDIR /opt/core
# configure.ac hard-codes ./venv/bin/python and refuses to run without it,
# so the venv is part of the build, not a convenience.
RUN python -m venv --system-site-packages venv && \
    ./venv/bin/pip install --no-cache-dir grpcio==1.69.0 grpcio-tools==1.69.0 \
      protobuf==5.29.3 fabric==3.2.2 invoke==2.2.0 lxml==5.2.2 \
      netaddr==0.10.1 Mako==1.2.3 PyYAML==6.0.1 pillow==11.1.0 pyproj==3.6.1
# vnoded and vcmd: CORE's own C programs. The daemon will not start
# without them, so a fork owns this build too.
RUN ./bootstrap.sh && ./configure --prefix=/usr && make -j4 && make install
# --- the first Throughline change to CORE, made here to prove the fork
# is modifiable before a fork exists ---
# CORE labels every link end with the addresses it invented for the lab.
# When a node is a program that is really running, those addresses are
# fiction and they bury the one label that is true: the program's name.
# Off by default; the View menu still turns them back on.
# The constructor default is not enough: joining a session calls a
# reset that sets both back to True, which is why changing only the
# default appeared to do nothing. Both sites, or neither.
RUN sed -i \
      -e 's/self.show_ip4s: BooleanVar = BooleanVar(value=True)/self.show_ip4s: BooleanVar = BooleanVar(value=False)/' \
      -e 's/self.show_ip6s: BooleanVar = BooleanVar(value=True)/self.show_ip6s: BooleanVar = BooleanVar(value=False)/' \
      -e 's/self.show_ip4s.set(True)/self.show_ip4s.set(False)/' \
      -e 's/self.show_ip6s.set(True)/self.show_ip6s.set(False)/' \
      /opt/core/daemon/core/gui/graph/manager.py \
 && ! grep -qE "show_ip[46]s(: BooleanVar = BooleanVar\\(value=True\\)|\\.set\\(True\\))" \
      /opt/core/daemon/core/gui/graph/manager.py
WORKDIR /opt/core/daemon
RUN /opt/core/venv/bin/python -m grpc_tools.protoc -I proto \
      --python_out=. --grpc_python_out=. proto/core/api/grpc/*.proto
# Its pyproject uses the poetry backend; an editable install would drag
# poetry-core in for no benefit here. PYTHONPATH runs it as-is.
ENV PYTHONPATH=/opt/core/daemon
# This container runs as root, and both scanners are right to say so.
# It is a stated exception rather than an oversight:
#
# CORE's daemon creates network namespaces and bind-mounts each node's
# filesystem. Those need CAP_SYS_ADMIN in the daemon process itself, and
# the daemon is Python -- an interpreter cannot carry file capabilities,
# so there is no non-root user that could do this work. Upstream runs it
# as root too, as a systemd unit on the host.
#
# What replaces the missing USER is the isolation this is run with:
# --network none (its own empty network namespace, so nothing it does
# reaches the host's networking), exactly two capabilities, no host
# mounts, and never --privileged. See README.md.
COPY run.sh /run.sh
COPY bridge.py /bridge.py
COPY run-bridge.sh /run-bridge.sh
RUN chmod +x /run.sh /run-bridge.sh
# nosemgrep: dockerfile.security.missing-user.missing-user
CMD ["/run.sh"]
