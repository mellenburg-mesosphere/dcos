import atexit
import os


if 'DCOS_IMAGE_COMMIT' not in os.environ:
    # This must be set for gen/build_deploy/util.py to be imported
    # which is required by gen for bash validation
    os.environ['DCOS_IMAGE_COMMIT'] = 'deadbeef'
    atexit.register(os.unsetenv, 'DCOS_IMAGE_COMMIT')
