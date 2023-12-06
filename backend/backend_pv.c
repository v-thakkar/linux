// SPDX-License-Identifier: GPL-2.0-only
/*
 * Implementation of pv backend driver for demo-sme
*/
#include <linux/init.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>

#include <xen/xen.h>
#include <xen/xenbus.h>
#include <xen/page.h>
#include <xen/events.h>
#include "../pv_device.h"

#define PROC_NAME "sme_domid"
#define BUF_SIZE 16

static char proc_buffer[BUF_SIZE];
static unsigned long proc_buffer_size = 0;

static struct proc_dir_entry *entry;

struct xensme_backend_info {
    struct xenbus_device *dev;
		struct smepv_back_ring ring;
    grant_ref_t gref;
    unsigned int evtchn;
    unsigned int irq;  
	  domid_t frontend_domid;
};

static ssize_t proc_write(struct file *filp, const char __user *buffer, size_t count, loff_t *offp) {
    proc_buffer_size = count;
    if (proc_buffer_size > BUF_SIZE)
        proc_buffer_size = BUF_SIZE;

    if (copy_from_user(proc_buffer, buffer, proc_buffer_size))
        return -EFAULT;

    proc_buffer[proc_buffer_size - 1] = '\0';

    printk(KERN_INFO "backend_module: Received domid = %s\n", proc_buffer);
    return proc_buffer_size;
}
 
static const struct proc_ops proc_file_fops = {
    .proc_write = proc_write,
};

 static void backend_connect(struct xenbus_device *dev)
{
		struct xensme_backend_info *info;
    //struct smepv_rx_back_ring rx;
    struct smepv_response *rsp;
    struct smepv_sring *rxs;
    unsigned int ring_ref;
    evtchn_port_t evtchn;
    struct evtchn_bind_interdomain bind_interdomain;
    void *addr;
    int err;
		int notify;

		pr_info("connecting the backend now\n");
    err = xenbus_gather(XBT_NIL, dev->otherend, "ring-ref", 
											"%u", &ring_ref, "event-channel", "%u", &evtchn, NULL);
		pr_info("ring ref and event channel binded");
    if(err) {
        xenbus_dev_fatal(dev, err, "reading %s/ring-ref", dev->otherend);
        return;
    }

    err = xenbus_map_ring_valloc(dev, (grant_ref_t *) &ring_ref, 1, &addr);
		pr_info("allocating ring succedded");
    if (err)
        return;

    rxs = (struct smepv_sring *)addr;
    BACK_RING_INIT(&info->ring, rxs, XEN_PAGE_SIZE);

    /*err = xenbus_gather(XBT_NIL, dev->otherend, "event-channel",
            "%u", &evtchn, NULL);
    if (err < 0) {
        xenbus_dev_fatal(dev, err, "reading %s/event-channel", dev->otherend);
        return;
    }*/

    // Allocates a new channel and binds it to the remote domain's port 
    bind_interdomain.remote_dom = dev->otherend_id;
    bind_interdomain.remote_port = evtchn;
    err = HYPERVISOR_event_channel_op(EVTCHNOP_bind_interdomain, &bind_interdomain);
		pr_info("binding inter domain succeded");
    if (err != 0) {
        pr_err("EVTCHNOP_bind_interdomain failed: %d\n", err);
        return;
    }

    rsp = RING_GET_RESPONSE(&info->ring, info->ring.rsp_prod_pvt);
		info->ring.rsp_prod_pvt++;
    snprintf(rsp->msg, sizeof(rsp->msg), "%s\n", "Hello World from backend");
    RING_PUSH_RESPONSES_AND_CHECK_NOTIFY(&info->ring, notify);

		if(notify);
    	notify_remote_via_irq(info->irq);
		pr_info("reached the end of backend_connect function");
}

static void backend_disconnect(struct xenbus_device *dev)
{
    pr_info("Disconnecting the sme backend now\n");
}

static void set_backend_state(struct xenbus_device *dev,
			      enum xenbus_state state)
{
	while (dev->state != state) {
		switch (dev->state) {
		case XenbusStateInitialising:
			switch (state) {
			case XenbusStateInitWait:
			case XenbusStateConnected:
			case XenbusStateClosing:
				xenbus_switch_state(dev, XenbusStateInitWait);
				break;
			case XenbusStateClosed:
				xenbus_switch_state(dev, XenbusStateClosed);
				break;
			default:
				BUG();
			}
			break;
		case XenbusStateClosed:
			switch (state) {
			case XenbusStateInitWait:
			case XenbusStateConnected:
				xenbus_switch_state(dev, XenbusStateInitWait);
				break;
			case XenbusStateClosing:
				xenbus_switch_state(dev, XenbusStateClosing);
				break;
			default:
				BUG();
			}
			break;
		case XenbusStateInitWait:
			switch (state) {
			case XenbusStateConnected:
				backend_connect(dev);
				xenbus_switch_state(dev, XenbusStateConnected);
				break;
			case XenbusStateClosing:
			case XenbusStateClosed:
				xenbus_switch_state(dev, XenbusStateClosing);
				break;
			default:
				BUG();
			}
			break;
		case XenbusStateConnected:
			switch (state) {
			case XenbusStateInitWait:
			case XenbusStateClosing:
			case XenbusStateClosed:
				backend_disconnect(dev);
				xenbus_switch_state(dev, XenbusStateClosing);
				break;
			default:
				BUG();
			}
			break;
		case XenbusStateClosing:
			switch (state) {
			case XenbusStateInitWait:
			case XenbusStateConnected:
			case XenbusStateClosed:
				xenbus_switch_state(dev, XenbusStateClosed);
				break;
			default:
				BUG();
			}
			break;
		default:
			BUG();
		}
	}
}

static void sme_frontend_changed(struct xenbus_device *dev, enum xenbus_state frontend_state)
{
 switch (frontend_state) {
		case XenbusStateInitialising:
			set_backend_state(dev, XenbusStateInitWait);
			break;

		case XenbusStateInitialised:
			break;

		case XenbusStateConnected:
			set_backend_state(dev, XenbusStateConnected);
			break;

		case XenbusStateClosing:
			set_backend_state(dev, XenbusStateClosing);
			break;

		case XenbusStateClosed:
			set_backend_state(dev, XenbusStateClosed);
			if (xenbus_dev_is_online(dev))
				break;
			fallthrough;
		case XenbusStateUnknown:
			set_backend_state(dev, XenbusStateClosed);
			device_unregister(&dev->dev);
			break;

		default:
			xenbus_dev_fatal(dev, -EINVAL, "saw state %s (%d) at frontend",
					xenbus_strstate(frontend_state), frontend_state);
			break;
	}   
}
static int xensme_backend_probe(struct xenbus_device *dev,
                                const struct xenbus_device_id *id)
{
    printk(KERN_NOTICE "Backend probe called\n");
		struct xensme_backend_info *info;
		
    //printk(KERN_NOTICE "Backend probe called\n");

		info = kzalloc(sizeof(struct xensme_backend_info), GFP_KERNEL);

		//pr_debug("%s %p %d\n", __func__, dev, dev->otherend_id);

		if (!info) {
			xenbus_dev_fatal(dev, -ENOMEM, "allocating backend structure");
			return -ENOMEM;
		}
		info->dev = dev;
		dev_set_drvdata(&dev->dev, info);

    xenbus_switch_state(dev, XenbusStateInitialising);
	
    return 0;
}

// TODO: Might need to implement this later?
/*static int xensme_backend_remove(struct xenbus_device *dev)
{

}*/

static const struct xenbus_device_id xensme_backend_ids[] = {
    { "sme" },
    { "" }
};

static struct xenbus_driver xensme_backend_driver = {
    .ids = xensme_backend_ids,
    .probe = xensme_backend_probe,
    //.remove = xensme_backend_remove,
    .otherend_changed = sme_frontend_changed,
};

static int __init xensme_backend_init(void) {
    if (!xen_domain())
        return -ENODEV;
    
    // Create /proc entry
    entry = proc_create(PROC_NAME, 0666, NULL, &proc_file_fops);

    if (!entry) {
        printk(KERN_INFO "backend module cannot create /proc/%s entry \n", PROC_NAME);
        return -ENOMEM;
    }

    printk(KERN_INFO "Backend SME PV driver initialized with /proc/%s\n", PROC_NAME);
    
    return xenbus_register_backend(&xensme_backend_driver);
}
module_init(xensme_backend_init);

static void __exit xensme_backend_exit(void) {
    // Remove /proc entry
    proc_remove(entry);
    pr_info("Backend PV driver exited\n");

    xenbus_unregister_driver(&xensme_backend_driver);
}
module_exit(xensme_backend_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Backend PV Driver for SME demo");
