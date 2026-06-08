try:
    import docker
except ImportError:
    docker = None
import tarfile
import io
import time
from typing import Tuple, Optional
from src.config import settings

class DockerSandbox:
    """
    Secure execution environment using Docker containers.
    """
    def __init__(self, image: str = "python:3.10-slim", timeout: int = 30):
        self.image = image
        self.timeout = timeout
        self.client = docker.from_env()
        self._ensure_image()

    def _ensure_image(self):
        """Ensure the target image exists locally."""
        try:
            self.client.images.get(self.image)
        except docker.errors.ImageNotFound:
            print(f"[Sandbox] Pulling image {self.image}...")
            self.client.images.pull(self.image)

    def run_code(self, code: str) -> str:
        """
        Execute Python code in a container.
        
        Args:
            code: Python code to execute.
            
        Returns:
            Combined stdout and stderr.
        """
        container = None
        try:
            # Create a container that keeps running
            container = self.client.containers.run(
                self.image,
                command="tail -f /dev/null",  # Keep alive
                detach=True,
                mem_limit="128m",
                network_disabled=True,        # No network by default
                security_opt=["no-new-privileges"]
            )
            
            # Prepare code script
            code_script = code.encode('utf-8')
            
            # Copy code to container
            tar_stream = io.BytesIO()
            with tarfile.open(fileobj=tar_stream, mode='w') as tar:
                tarinfo = tarfile.TarInfo(name='script.py')
                tarinfo.size = len(code_script)
                tar.addfile(tarinfo, io.BytesIO(code_script))
            tar_stream.seek(0)
            
            container.put_archive('/tmp', tar_stream)
            
            # Execute code
            exec_result = container.exec_run(
                "python /tmp/script.py",
                workdir="/tmp",
                demux=True # Separate stdout/stderr
            )
            
            stdout, stderr = exec_result.output
            
            result = ""
            if stdout:
                result += stdout.decode('utf-8', errors='replace')
            if stderr:
                result += f"\n[STDERR]\n{stderr.decode('utf-8', errors='replace')}"
                
            return result or "Code executed successfully (no output)"

        except Exception as e:
            return f"Sandbox Error: {str(e)}"
            
        finally:
            if container:
                try:
                    container.kill()
                    container.remove()
                except Exception:
                    pass

# Singleton if needed, but per-execution is safer for now
