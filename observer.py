# observer.py - ACTUALIZADO
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from config import DEFAULT_CONF, ALERT_COOLDOWN
from database import register_incident
from datetime import datetime
import time


class Subject(ABC):
    @abstractmethod
    def attach(self, observer: 'Observer') -> None:
        pass

    @abstractmethod
    def detach(self, observer: 'Observer') -> None:
        pass

    @abstractmethod
    def notify(self, event_data: dict) -> None:
        pass


class SafetyMonitorSubject(Subject):
    """
    Subject para monitoreo de seguridad: Notifica eventos como alertas EPP/intrusión.
    Instancias independientes mantienen su propio cooldown y lista de observers.
    """

    def __init__(self):
        self._state = {}
        self._observers: List['Observer'] = []
        self._last_alert_time: float = 0

    def attach(self, observer: 'Observer') -> None:
        print(f"SafetyMonitorSubject: Attached observer {type(observer).__name__}.")
        self._observers.append(observer)

    def detach(self, observer: 'Observer') -> None:
        if observer in self._observers:
            self._observers.remove(observer)

    def notify(self, event_data: dict) -> None:
        ahora = time.time()
        if ahora - self._last_alert_time < ALERT_COOLDOWN:
            print('Cooldown activo: omitiendo notificación')
            return  # Cooldown
        self._last_alert_time = ahora

        print(f"SafetyMonitorSubject: Notifying observers with event: {event_data}")
        for observer in list(self._observers):
            try:
                observer.update(self, event_data)
            except Exception as e:
                print(f"Error notifying observer {type(observer).__name__}: {e}")

    def detect_event(self, classes_detected: List[str], camera_name: str,
                     user_identified: Optional[Dict[str, str]] = None,
                     evidence_path: Optional[str] = None) -> None:
        """
        Lógica de negocio: Detecta y notifica si falta EPP o intrusión.
        - `classes_detected` espera items con posición: e.g. 'helmet_1', 'vest_1', 'qr_head_1', 'qr_body_2'
        - `user_identified` es un dict opcional que mapea ubicacion->qr_value: {'head': 'QR123', 'body': 'QR456'}
        """
        # Agrupar detecciones por persona (por índice numérico en los nombres)
        people = self._group_detections(classes_detected, user_identified or {})

        # Verificar intrusión global (si hay clases intrusión)
        intrusion = any(c.startswith('intrusion') or c.startswith('not_') for c in classes_detected)

        # Para cada persona generar alertas por falta de equipo
        for person in people:
            has_helmet = person.get('helmet', False)
            has_vest = person.get('vest', False)
            user_id = person.get('user_id') or 'unknown'

            # Falta casco
            if not has_helmet:
                severity = self.calculate_william_fine(prob=0.8, exp=3, cons=10)
                event_data = {
                    'alert_type': 'Falta Casco',
                    'camera': camera_name,
                    'severity': severity,
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'user_identified': user_id,
                    'description': f"Falta casco de protección - Usuario: {user_id}",
                    'evidence_path': evidence_path,
                    'classes_detected': classes_detected,
                }
                self.notify(event_data)

            # Falta chaleco
            if not has_vest:
                severity = self.calculate_william_fine(prob=0.8, exp=3, cons=10)
                event_data = {
                    'alert_type': 'Falta Chaleco',
                    'camera': camera_name,
                    'severity': severity,
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'user_identified': user_id,
                    'description': f"Falta chaleco reflectivo - Usuario: {user_id}",
                    'evidence_path': evidence_path,
                    'classes_detected': classes_detected,
                }
                self.notify(event_data)

        # Si detectamos intrusión, notificar una alerta genérica de intrusión
        if intrusion:
            severity = self.calculate_william_fine(prob=0.6, exp=2, cons=7)
            event_data = {
                'alert_type': 'Intrusión',
                'camera': camera_name,
                'severity': severity,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'user_identified': 'unknown',
                'description': 'Intrusión detectada',
                'evidence_path': evidence_path,
                'classes_detected': classes_detected,
            }
            self.notify(event_data)

    def _group_detections(self, classes_detected: List[str], qr_data: Dict[str, str]) -> List[Dict[str, Any]]:
        """
        Agrupa las detecciones por persona usando el sufijo numérico en las etiquetas.
        Retorna una lista de dicts: {'helmet': bool, 'vest': bool, 'user_id': str}

        Ejemplo de `classes_detected` esperado:
          ['helmet_1', 'qr_head_1', 'vest_1', 'qr_body_2']
        Ejemplo de `qr_data`:
          {'head': 'QR123', 'body': 'QR456'}
        """
        people: Dict[int, Dict[str, Any]] = {}

        for item in classes_detected:
            # Esperamos formato con guion bajo y número al final
            if '_' not in item:
                continue
            base, idx = item.rsplit('_', 1)
            if not idx.isdigit():
                continue
            pid = int(idx)
            if pid not in people:
                people[pid] = {'helmet': False, 'vest': False, 'user_id': None}

            # base puede incluir ubicacion, ej 'qr_head' o 'qr_body'
            if base == 'helmet':
                people[pid]['helmet'] = True
            elif base in ('vest', 'reflective'):
                people[pid]['vest'] = True
            elif base.startswith('qr'):
                # determinar si el tag contiene la palabra head/body
                if 'head' in base and 'head' in qr_data:
                    people[pid]['user_id'] = qr_data.get('head')
                elif 'body' in base and 'body' in qr_data:
                    people[pid]['user_id'] = qr_data.get('body')
                else:
                    # si no hay posición en el nombre, intentar asignar el primer valor disponible
                    if qr_data:
                        first = next(iter(qr_data.values()))
                        people[pid]['user_id'] = first

        # Devolver lista ordenada por pid para determinismo
        return [people[k] for k in sorted(people.keys())]

    def calculate_william_fine(self, prob: float, exp: int, cons: int) -> int:
        """Método William Fine para priorizar (Prob x Exp x Cons)."""
        return int(prob * exp * cons)


class Observer(ABC):
    @abstractmethod
    def update(self, subject: Subject, event_data: dict) -> None:
        pass


class AlertLogger(Observer):
    """Observer: Loggea alertas en GUI o consola."""

    def __init__(self, log_widget=None):
        self.log_widget = log_widget

    def update(self, subject: Subject, event_data: dict) -> None:
        # No mostrar Severidad en el mensaje, pero usarla para color
        color = 'yellow' if event_data.get('severity', 0) < 15 else 'red'

        # Construir información de usuario según detecciones
        user_info = ''
        classes_detected = event_data.get('classes_detected', [])
        user_ident = event_data.get('user_identified')

        if user_ident and user_ident != 'unknown':
            # determinar si el QR corresponde a cabeza o cuerpo según classes_detected
            # si hay múltiples QR por persona, asumimos que el evento trae user_identified ya diferenciado
            if any('qr' in c for c in classes_detected) and not any(x in classes_detected for x in ('reflective', 'vest')):
                user_info = f" - Solo QR: {user_ident}"
            elif any(x in classes_detected for x in ('reflective', 'vest')) and not any('qr' in c for c in classes_detected):
                user_info = f" - Solo chaleco: {user_ident}"
            else:
                user_info = f" - Usuario: {user_ident}"
        else:
            user_info = ' - Usuario: unknown'

        msg = f"[{event_data.get('timestamp')}] {event_data.get('camera')}: {event_data.get('alert_type')}{user_info}"

        if self.log_widget:
            try:
                self.log_widget.append(f"<span style='color: {color};'>🚨 {msg}</span>")
            except Exception:
                print(f"ALERTA(widget): {msg}")
        else:
            print(f"ALERTA: {msg}")


class IncidentRegistrar(Observer):
    """Observer: Registra en DB si severidad > umbral."""

    def update(self, subject: Subject, event_data: dict) -> None:
        try:
            if event_data.get('severity', 0) > 5:  # Umbral configurable
                register_incident(
                    event_data.get('camera'),
                    event_data.get('alert_type'),
                    event_data.get('description'),
                    event_data.get('user_identified'),
                    event_data.get('evidence_path')
                )
                print(f"Incidente registrado en DB: {event_data.get('alert_type')}")
        except Exception as e:
            print(f"Error registrando incidente: {e}")


class RankingUpdater(Observer):
    """Observer: Actualiza ranking de cámaras por incidentes."""

    def __init__(self, ranking_counter: dict):
        self.ranking_counter = ranking_counter

    def update(self, subject: Subject, event_data: dict) -> None:
        camera_name = event_data.get('camera')
        self.ranking_counter[camera_name] = self.ranking_counter.get(camera_name, 0) + 1
        print(f"Ranking actualizado: {camera_name} = {self.ranking_counter[camera_name]} alertas.")