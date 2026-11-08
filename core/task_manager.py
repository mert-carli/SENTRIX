import threading
import uuid
import time
from concurrent.futures import ThreadPoolExecutor, Future
from typing import Callable, Dict, Any, Optional, List
from core.event_bus import event_bus

class TaskStatus:
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"

class TaskContext:
    def __init__(self, task_id: str, name: str, cancel_event: threading.Event):
        self.task_id = task_id
        self.name = name
        self._cancel_event = cancel_event
        self.progress = 0.0
        self.message = ""

    def is_cancelled(self) -> bool:
        return self._cancel_event.is_set()

    def update_progress(self, percent: float, message: str = ""):
        self.progress = max(0.0, min(100.0, percent))
        self.message = message
        event_bus.publish("TASK_PROGRESS", {
            "task_id": self.task_id,
            "name": self.name,
            "progress": self.progress,
            "message": self.message
        })

class TaskManager:
    def __init__(self, max_workers: int = 10):
        self.executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="SentrixWorker")
        self.tasks: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()

    def run_task(self, name: str, target: Callable[[TaskContext], Any], timeout: Optional[float] = None) -> str:
        task_id = str(uuid.uuid4())[:8]
        cancel_event = threading.Event()
        context = TaskContext(task_id, name, cancel_event)

        task_record = {
            "id": task_id,
            "name": name,
            "status": TaskStatus.QUEUED,
            "context": context,
            "cancel_event": cancel_event,
            "future": None,
            "start_time": None,
            "end_time": None,
            "result": None,
            "error": None
        }

        with self._lock:
            self.tasks[task_id] = task_record

        def worker_wrapper():
            task_record["status"] = TaskStatus.RUNNING
            task_record["start_time"] = time.time()
            event_bus.publish("TASK_STATUS_CHANGED", {"task_id": task_id, "status": TaskStatus.RUNNING, "name": name})

            try:
                if context.is_cancelled():
                    task_record["status"] = TaskStatus.CANCELLED
                    return None

                res = target(context)
                
                if context.is_cancelled():
                    task_record["status"] = TaskStatus.CANCELLED
                else:
                    task_record["status"] = TaskStatus.COMPLETED
                    task_record["result"] = res
                return res
            except Exception as e:
                task_record["status"] = TaskStatus.FAILED
                task_record["error"] = str(e)
                return None
            finally:
                task_record["end_time"] = time.time()
                event_bus.publish("TASK_STATUS_CHANGED", {
                    "task_id": task_id, 
                    "status": task_record["status"], 
                    "name": name,
                    "error": task_record["error"]
                })

        future = self.executor.submit(worker_wrapper)
        task_record["future"] = future

        event_bus.publish("TASK_QUEUED", {"task_id": task_id, "name": name})
        return task_id

    def cancel_task(self, task_id: str) -> bool:
        with self._lock:
            if task_id in self.tasks:
                record = self.tasks[task_id]
                record["cancel_event"].set()
                if record["status"] in [TaskStatus.QUEUED, TaskStatus.RUNNING]:
                    record["status"] = TaskStatus.CANCELLED
                    event_bus.publish("TASK_STATUS_CHANGED", {"task_id": task_id, "status": TaskStatus.CANCELLED, "name": record["name"]})
                return True
        return False

    def get_task(self, task_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self.tasks.get(task_id)

    def get_active_tasks(self) -> Dict[str, Dict[str, Any]]:
        with self._lock:
            return {
                tid: t for tid, t in self.tasks.items() 
                if t["status"] in [TaskStatus.QUEUED, TaskStatus.RUNNING]
            }

    def get_task_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            all_tasks = sorted(self.tasks.values(), key=lambda t: t.get("start_time") or 0, reverse=True)
            return all_tasks[:limit]

    def shutdown(self, wait: bool = False):
        with self._lock:
            for task_id, record in self.tasks.items():
                if record["status"] in [TaskStatus.QUEUED, TaskStatus.RUNNING]:
                    record["cancel_event"].set()
                    record["status"] = TaskStatus.CANCELLED
        self.executor.shutdown(wait=wait, cancel_futures=True)

task_manager = TaskManager()
