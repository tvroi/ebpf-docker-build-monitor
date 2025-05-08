from kafka import KafkaProducer
import json
import logging
from typing import Dict, Any, Optional

class KafkaHelper:
    _instance = None
    
    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(KafkaHelper, cls).__new__(cls)
            cls._instance.initialized = False
        return cls._instance
    
    def __init__(self, brokers="1.1.1.1", batch_size=16384, 
                 linger_ms=5, acks="all", retries=3):
        
        if self.initialized:
            return
        
        self.logger = logging.getLogger(__name__)
        
        self.producer = KafkaProducer(
            bootstrap_servers=brokers,
            value_serializer=lambda v: json.dumps(v).encode('utf-8'),
            acks=acks,
            retries=retries,
            batch_size=batch_size,
            linger_ms=linger_ms,
            buffer_memory=33554432
        )
        self.initialized = True
        self.logger.info("Kafka producer initialized with brokers: %s", brokers)
    
    def send(self, topic: str, payload: Dict[str, Any], key: Optional[str] = None, callback=None):

        try:
            self.logger.debug(f"Sending to {topic}: {payload}")
            
            encoded_key = key.encode('utf-8') if key else None
            
            future = self.producer.send(
                topic, 
                payload, 
                key=encoded_key
            )
            
            if callback:
                future.add_callback(callback)
            else:
                future.add_callback(self._on_send_success, self._on_send_error)
                
            return future
            
        except Exception as e:
            self.logger.error(f"Error sending to Kafka: {str(e)}")
            raise
    
    def _on_send_success(self, record_metadata):
        self.logger.debug(f"Message sent successfully to {record_metadata.topic}, "
                         f"partition: {record_metadata.partition}, "
                         f"offset: {record_metadata.offset}")
    
    def _on_send_error(self, exc):
        self.logger.error(f"Failed to send message to Kafka: {str(exc)}")
    
    def flush(self):
        self.producer.flush()
    
    def close(self):
        self.producer.flush()
        self.producer.close()
        self.logger.info("Kafka producer closed")