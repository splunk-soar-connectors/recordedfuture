from invoke import task, Collection
RELEASE = "4.4.3"
BUILD_DIR = "pkg_build"
PACKAGE = f"recordedfuture-{RELEASE}.tgz"


@task
def clean(c):
    """
    Removes build directory and earlier packaged release
    """
    c.run(f"rm -rf {BUILD_DIR}")
    c.run(f"rm -rf {PACKAGE}")


@task(clean)
def build(c):
    """Collect everything to pkg_build directory"""
    c.run(f"""
        rsync -ra . {BUILD_DIR} \
            --exclude=*.pyc \
            --exclude=.github \
            --exclude=tasks.py \
            --exclude=.git \
            --exclude=*.tgz \
            --exclude=venv \
            --exclude=pkg_build \
    """)


@task(build)
def package(c):
    """Package the app for development"""
    c.run(f"tar cvfz {PACKAGE} pkg_build")
