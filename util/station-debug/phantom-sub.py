import redis
import signalling_pb2 as proto
import datetime

red = redis.StrictRedis('localhost', 6379, charset="utf-8", decode_responses=False)

def pb_op(i):
    if i in proto._STATIONOPERATIONS.values_by_number:
        return proto._STATIONOPERATIONS.values_by_number[i].name
    return ""

def pb_proto(i):
    if i in proto._IPPROTO.values_by_number:
        return proto._IPPROTO.values_by_number[i].name
    return ""

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
        op = pb_op(s2d.operation).lower()
        pro = pb_proto(s2d.proto).lower()
        print('%s %s %s %s:%s :%d %d' % \
                (datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f"), op, s2d.client_ip, pro, s2d.phantom_ip, s2d.dst_port, int(s2d.timeout_ns/1000000000.0)))


