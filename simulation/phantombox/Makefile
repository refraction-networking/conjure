
VMS = station tap pt

vms : $(VMS)

.PHONY: vms

all : vms

station : clean-station station/cidata.iso images/station.qcow2
	@[ "${CONJURE_STATION_REPO}" ] || ( echo "Env var CONJURE_STATION_REPO is not set."; exit 1 )
	virt-install --name=station --ram=6144 --vcpus=2 --cpu mode=host-passthrough --import --disk path=images/station.qcow2,format=qcow2 --disk path=station/cidata.iso,device=cdrom --os-variant=ubuntu20.04 --network network=default,mac='52:54:00:00:01:02' --network network=tap,mac='52:54:00:00:02:02',model='e1000e' --noautoconsole --filesystem="source=\"$(CONJURE_STATION_REPO)\",target='/repo',accessmode='passthrough'" --memorybacking access.mode='shared'
	$(info ********** Installing station ***********)
	$(info ********* this may take a while *********)
	sleep 6m

pt : clean-pt pt/cidata.iso images/pt.qcow2 tap
	@[ "${CONJURE_PT_REPO}" ] || ( echo "Env var CONJURE_PT_REPO is not set."; exit 1 )
	virt-install --name=pt --ram=2048 --vcpus=2 --cpu mode=host-passthrough --import --disk path=images/pt.qcow2,format=qcow2 --disk path=pt/cidata.iso,device=cdrom --os-variant=ubuntu20.04 --network network=default,mac='52:54:00:00:01:03' --network network=tap,mac='52:54:00:00:02:03' --noautoconsole --filesystem="source=\"$(CONJURE_PT_REPO)\",target='/repo',accessmode='passthrough'" --memorybacking access.mode='shared'
	$(info ********** Installing pt ***********)
	$(info ********* this may take a while *********)
	sleep 2m

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

shutdown: shutdown-tap shutdown-pt shutdown-station

start-% :
	virsh start $*

start: start-tap start-pt start-station

clean-% : shutdown
	-virsh undefine $*
	rm -f images/$*.qcow2
	rm -f $*/cidata.iso

clean : clean-station clean-pt clean-tap
	ssh-keygen -f "$(HOME)/.ssh/known_hosts" -R "192.168.122.2"
	ssh-keygen -f "$(HOME)/.ssh/known_hosts" -R "192.168.122.3"
	ssh-keygen -f "$(HOME)/.ssh/known_hosts" -R "192.168.122.4"
