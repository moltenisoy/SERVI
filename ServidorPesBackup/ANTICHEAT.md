# Sistema Anti-Cheat / Anti-Cheat System

## Descripción General / Overview

El sistema anti-cheat implementado proporciona protección integral contra múltiples tipos de trampas y manipulaciones en el servidor PES5/PES6:

The implemented anti-cheat system provides comprehensive protection against multiple types of cheating and manipulation on the PES5/PES6 server:

## Características / Features

### 1. Protección contra Cheat Engine / Cheat Engine Protection

**Detecta y previene:**
- Manipulación de valores de memoria (puntos, estadísticas, goles)
- Valores imposibles o fuera de rango
- Cambios sospechosos en estadísticas de jugador

**Detects and prevents:**
- Memory value manipulation (points, stats, goals)
- Impossible or out-of-range values
- Suspicious changes in player statistics

**Implementación:**
- Validación de rangos de valores en tiempo real
- Seguimiento histórico de valores para detectar cambios anormales
- Verificación de checksums de paquetes

### 2. Detección de Lag Intencional / Intentional Lag Detection

**Detecta:**
- Patrones de lag switch (alternancia rápida entre conexión rápida/lenta)
- Spikes de latencia sospechosos
- Comportamiento de red inconsistente

**Detects:**
- Lag switch patterns (rapid alternation between fast/slow connection)
- Suspicious latency spikes
- Inconsistent network behavior

**Implementación:**
- Análisis de temporización de paquetes
- Detección de patrones alternantes
- Puntuación de anomalías basada en comportamiento

### 3. Verificación de Versión del Cliente / Client Version Verification

**Previene:**
- Clientes modificados o hackeados
- Versiones no autorizadas del juego
- Modificaciones de ejecutables

**Prevents:**
- Modified or hacked clients
- Unauthorized game versions
- Executable modifications

**Implementación:**
- Verificación de hash de roster
- Lista configurable de versiones conocidas legítimas
- Rechazo opcional de clientes desconocidos

### 4. Monitoreo de Comportamiento de Red / Network Behavior Monitoring

**Detecta:**
- Limitadores de red artificiales
- Throttling de ancho de banda
- Patrones de spam de paquetes
- Manipulación de conexión

**Detects:**
- Artificial network limiters
- Bandwidth throttling
- Packet spam patterns
- Connection manipulation

**Implementación:**
- Análisis de ancho de banda en tiempo real
- Detección de patrones de envío de paquetes
- Monitoreo de tamaño y frecuencia de paquetes

## Configuración / Configuration

### Archivo de Configuración / Configuration File

Agregar a `fiveserver.yaml` o `sixserver.yaml`:

```yaml
AntiCheat:
    enabled: true                    # Activar/desactivar sistema anti-cheat
    ban_threshold: 100               # Puntuación para ban automático
    reject_unknown_clients: false    # Rechazar clientes desconocidos
    # Lista de hashes de clientes conocidos (opcional)
    # known_client_hashes:
    #   - "hash_del_cliente_legitimo_1"
    #   - "hash_del_cliente_legitimo_2"
```

### Parámetros / Parameters

- **`enabled`**: Activa o desactiva el sistema completo (default: `true`)
- **`ban_threshold`**: Puntuación de violaciones necesaria para ban automático (default: `100`)
- **`reject_unknown_clients`**: Si es `true`, rechaza clientes con hashes desconocidos (default: `false`)
- **`known_client_hashes`**: Lista opcional de hashes MD5 de clientes legítimos conocidos

## Sistema de Puntuación / Scoring System

El sistema asigna puntos por diferentes tipos de violaciones:

The system assigns points for different types of violations:

| Tipo de Violación / Violation Type | Puntos / Points |
|-------------------------------------|-----------------|
| Spam de paquetes / Packet spam | 10 |
| Throttling de ancho de banda / Bandwidth throttling | 15 |
| Lag switch detectado / Lag switch detected | 25 |
| Versión de cliente desconocida / Unknown client version | 30 |
| Integridad de memoria / Memory integrity | 40 |
| Puntuación de partido imposible / Impossible match score | 40 |

**Ban automático:** Cuando la puntuación total alcanza `ban_threshold`, el usuario es desconectado automáticamente.

**Automatic ban:** When total score reaches `ban_threshold`, the user is automatically disconnected.

## Validaciones Implementadas / Implemented Validations

### Durante Autenticación / During Authentication
- Verificación de hash de cliente
- Validación de versión de juego

### Durante el Juego / During Gameplay
- Monitoreo de temporización de paquetes
- Análisis de ancho de banda
- Detección de patrones de spam

### Al Finalizar Partidas / After Matches
- Validación de puntuaciones (rango 0-99)
- Validación de duración del partido (60-7200 segundos)
- Verificación de estadísticas de jugador
- Validación de cambios en puntos

## Logs y Monitoreo / Logging and Monitoring

Todos los eventos anti-cheat se registran con el prefijo `ANTICHEAT:`:

All anti-cheat events are logged with the `ANTICHEAT:` prefix:

```
ANTICHEAT: Suspicious lag detected: 2.54s (packet: 0x4300)
ANTICHEAT: Bandwidth throttling detected for abc123: 856.32 B/s
ANTICHEAT: Unknown client hash detected for user def456
ANTICHEAT: Impossible match score detected: 255:128
ANTICHEAT: Ban threshold reached for user xyz789 (score: 105)
```

## Reportes por Usuario / Per-User Reports

El sistema mantiene reportes detallados para cada usuario:

The system maintains detailed reports for each user:

```python
{
    'violations': [
        {'type': 'packet_spam', 'timestamp': datetime},
        {'type': 'memory_integrity: impossible_points_value', 'timestamp': datetime}
    ],
    'score': 50,
    'timing_anomaly_score': 15,
    'should_ban': False
}
```

## Limpieza de Datos / Data Cleanup

- Los datos de análisis se limpian automáticamente cuando un usuario se desconecta
- El historial de violaciones se mantiene para reconexiones
- Los analizadores de temporización mantienen solo los últimos 100 paquetes

## Consideraciones de Rendimiento / Performance Considerations

- El sistema está optimizado para impacto mínimo en el rendimiento
- Las validaciones se ejecutan de forma asíncrona
- Los errores en el sistema anti-cheat no afectan la jugabilidad normal
- Ventanas de datos limitadas para evitar fugas de memoria

## Recomendaciones de Uso / Usage Recommendations

### Configuración Permisiva (Recomendada para inicio)
```yaml
AntiCheat:
    enabled: true
    ban_threshold: 150
    reject_unknown_clients: false
```

### Configuración Estricta (Para servidores competitivos)
```yaml
AntiCheat:
    enabled: true
    ban_threshold: 80
    reject_unknown_clients: true
    known_client_hashes:
      - "hash1"
      - "hash2"
```

### Configuración de Solo Monitoreo
```yaml
AntiCheat:
    enabled: true
    ban_threshold: 999999  # Efectivamente deshabilita bans automáticos
    reject_unknown_clients: false
```

## Solución de Problemas / Troubleshooting

### Problema: Falsos Positivos
**Solución:** Aumentar `ban_threshold` o ajustar umbrales específicos en el código

### Problema: Los tramposos no son detectados
**Solución:** Reducir `ban_threshold`, habilitar `reject_unknown_clients`, agregar hashes conocidos

### Problema: Jugadores legítimos rechazados
**Solución:** Deshabilitar `reject_unknown_clients` o agregar sus hashes a `known_client_hashes`

## Desarrollo Futuro / Future Development

Mejoras potenciales:
- Machine learning para detección de patrones
- Lista blanca/negra de IP
- Integración con sistemas externos de reputación
- Análisis de comportamiento más sofisticado
- Panel de administración web para revisar violaciones

## Créditos / Credits

Sistema anti-cheat implementado para el servidor SERVI PES5/PES6.
Basado en análisis de protocolo y comportamiento de red del juego.

Anti-cheat system implemented for SERVI PES5/PES6 server.
Based on protocol analysis and game network behavior.
