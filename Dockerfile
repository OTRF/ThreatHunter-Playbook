# THP script: Hunters Jupyter Dockerfile
# Author: Roberto Rodriguez (@Cyb3rWard0g)
# License: GPL-3.0

FROM cyb3rward0g/jupyter-hunt:0.0.1
LABEL maintainer="Roberto Rodriguez @Cyb3rWard0g"
LABEL description="Dockerfile Notebooks-Forge Jupyter-Hunt Project."

# ********** Adding HELK Jupyter notebooks
RUN mkdir /opt/helk/jupyter/notebooks/datasets