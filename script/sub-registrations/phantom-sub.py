import redis
import signalling_pb2 as proto

red = redis.StrictRedis('localhost', 6379, charset="utf-8", decode_responses=False)

sub = red.pubsub()
sub.subscribe('dark_decoy_map')
for message in sub.listen():
    if message is not None and isinstance(message, dict):
        data = message.get('data')

        if not isinstance(data, bytes):
            continue
        #print(data)
        s2d = proto.StationToDetector()
        s2d.ParseFromString(data)
        print('%s registered %s for %.3f seconds' % \
            (s2d.client_ip, s2d.phantom_ip, s2d.timeout_ns/1000000000.0))
