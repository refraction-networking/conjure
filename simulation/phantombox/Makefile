
VMS = station tap h1

vms : $(VMS)

.PHONY: vms

all : vms

station : clean-station station/cidata.iso images/station.qcow2
	@[ "${CONJURE_STATION_REPO}" ] || ( echo "Env var CONJURE_STATION_REPO is not set."; exit 1 )
	virt-install --name=station --ram=6144 --vcpus=2 --cpu mode=host-passthrough --import --disk path=images/station.qcow2,format=qcow2 --disk path=station/cidata.iso,device=cdrom --os-variant=ubuntu20.04 --network network=default,mac='52:54:00:00:01:02' --network network=tap,mac='52:54:00:00:02:02',model='e1000e' --noautoconsole --filesystem source="$(CONJURE_STATION_REPO)/",type='mount',driver.type='virtiofs',target='repo',accessmode='passthrough'  --memorybacking access.mode='shared'
	$(info ********** Installing station ***********)
	$(info ********* this may take a while *********)
	sleep 6m

h1 : clean-h1 h1/cidata.iso images/h1.qcow2 tap
ifdef CONJURE_H1_REPO
	@[ "${CONJURE_H1_REPO}" ] || ( echo "Env var CONJURE_H1_REPO is not set."; exit 1 )
	virt-install --name=h1 --ram=2048 --vcpus=2 --cpu mode=host-passthrough --import --disk path=images/h1.qcow2,format=qcow2 --disk path=h1/cidata.iso,device=cdrom --os-variant=ubuntu20.04 --network network=default,mac='52:54:00:00:01:03' --network network=tap,mac='52:54:00:00:02:03' --noautoconsole --filesystem source="$(CONJURE_H1_REPO)/",type='mount',driver.type='virtiofs',target='repo',accessmode='passthrough'   --memorybacking access.mode='shared'
else
	virt-install --name=h1 --ram=2048 --vcpus=2 --cpu mode=host-passthrough --import --disk path=images/h1.qcow2,format=qcow2 --disk path=h1/cidata.iso,device=cdrom --os-variant=ubuntu20.04 --network network=default,mac='52:54:00:00:01:03' --network network=tap,mac='52:54:00:00:02:03' --noautoconsole --memorybacking access.mode='shared'
endif
	$(info ********** Installing h1 ***********)
	sleep 1m

tap : clean-tap tap/cidata.iso images/tap.qcow2
	virt-install --name=tap --ram=1024 --vcpus=1 --cpu mode=host-passthrough --import --disk path=images/tap.qcow2,format=qcow2 --disk path=tap/cidata.iso,device=cdrom --os-variant=ubuntu20.04 --network network=default,mac='52:54:00:00:01:04' --network network=tap,mac='52:54:00:00:02:04' --noautoconsole
	$(info ********** Installing tap ***********)

%/cidata.iso : %/user-data %/meta-data %/network-config
	genisoimage -output $@ -V cidata -r -J $^

images/base.img :
	wget http://cloud-images.ubuntu.com/focal/current/focal-server-cloudimg-amd64.img -O $@

%.qcow2 : images/base.img
	qemu-img create -b base.img -f qcow2 -F qcow2 $@ 10G

shutdown-% :
	-virsh shutdown $*

shutdown: shutdown-tap shutdown-h1 shutdown-station

start-% :
	virsh start $*

start: start-tap start-h1 start-station

clean-% : shutdown
	-virsh undefine $*
	rm -f images/$*.qcow2
	rm -f $*/cidata.iso

clean : clean-station clean-h1 clean-tap

# don't run as sudo or permisions on your .ssh/known_hosts will be messed up.
clean-ssh :
	ssh-keygen -f "$(HOME)/.ssh/known_hosts" -R "192.168.122.2"
	ssh-keygen -f "$(HOME)/.ssh/known_hosts" -R "192.168.122.3"
	ssh-keygen -f "$(HOME)/.ssh/known_hosts" -R "192.168.122.4"
