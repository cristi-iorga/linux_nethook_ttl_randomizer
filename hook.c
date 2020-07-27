	/* 	

	this module was tested on a Lubuntu virtual machine 
	using Virtual Box 6.1.10
	running on a Macbook Pro (Late 2013), OS: 10.13.6
	The kernel version used to build the model is 5.4.0-26 generic

	*/


	/* 

	This kernel module takes outgoing TCP packet flows and incoming UDP packet flows
	and asigns them a random ttl (between 10 and 127).

	To keep track of the flows and their asigned ttl it uses a rudimentary hash table.

	TCP flows are deleted from the table when a packet arrives with the FIN flag set,
	whereas UDP flows are periodically deleted if they are not active anymore.

	Whenever a UDP packet from a certain flow arrives the first bit from the ttl is 
	set. This bit is only used to keep track if the flow is active or not. 

	*/ 

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h> 				// for ip header struct
#include <linux/tcp.h>				// for tcp header struct
#include <linux/udp.h>				// for udp header struct
#include <linux/types.h>			// uint8_t etc.
#include <linux/timer.h>			// for the timer struct
#include <asm/byteorder.h> 			// for byte order conversions

#define TABLE_SIZE 1000

#define HASH_FUNC(num) (num % TABLE_SIZE)
#define CHECK_FLOW(flow, ht) ((ht->entries[flow]!=NULL) ? 1  :  0) 
#define ACTIVE_BIT_NOT_SET(flow, ht) ((ht->entries[flow]->is_active==0) ? 1 :  0)

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Cristi Iorga");

static struct nf_hook_ops *hook_out = NULL;
static struct nf_hook_ops *hook_in = NULL;

/* -------------- this part takes care of the hash table data structure needed ---------------- */

/* let's use the first bit in the ttl to store the state of the flow: ative or inactive */
typedef struct{
	uint8_t is_active : 1;
	uint8_t ttl: 7;
} ht_entry;

/* note that this hashtable has no protection against collisions */
typedef struct{
	ht_entry **entries;
} hashtable_t;

/* let's declare our hashtable globally */
hashtable_t *hashtable_tcp;
hashtable_t *hashtable_udp;

void init_hash_tables(void){

	/* TCP TABLE */

	/* allocate memory for the table */
	hashtable_tcp = kcalloc(1, sizeof(hashtable_t), GFP_KERNEL);
	/* allocate memory for the entries and zero it */
	hashtable_tcp->entries = kzalloc(TABLE_SIZE * sizeof(ht_entry*), GFP_KERNEL);

	/* UDP TABLE */

	/* allocate memory for the table */
	hashtable_udp = kcalloc(1, sizeof(hashtable_t), GFP_KERNEL);
	/* allocate memory for the entries and zero them */
	hashtable_udp->entries = kzalloc(TABLE_SIZE * sizeof(ht_entry*), GFP_KERNEL);

	printk(KERN_INFO "Hashtables initialized!");
	printk(KERN_INFO "tcp table ptr: %p, udp table tr: %p", hashtable_tcp,  hashtable_udp);
	return;
}

void add_flow_to_table(int hash, hashtable_t *hashtable){

	ht_entry *new_entry;
	uint8_t random_ttl;

	/* let's check if the flow is found in the table */
	if(CHECK_FLOW(hash, hashtable)) {
		/* set the flag to 1 since the flag has been called */
		hashtable->entries[hash]->is_active = 1;
		return;
		}

	/* allocate memory for our new ttl */
	new_entry = kcalloc(1, sizeof(ht_entry), GFP_KERNEL); 

	/* let's generate a new ttl */
	get_random_bytes(&random_ttl, sizeof(uint8_t));

	/* let's chop off the first bit */
	random_ttl = random_ttl & 0x7F;

	/* make sure it's bigger that 10 */
	if(random_ttl<10) {random_ttl += 10;}

	/* add the new entry */
	new_entry->ttl = random_ttl;

	/* let's set the bit to active */
	new_entry->is_active = 1;

	/* add the new entry */
	hashtable->entries[hash] = new_entry;

	return;
}

/* this function returns the ttl for debugging purposes */ 
uint8_t delete_flow_id(int hash, hashtable_t *hashtable){

	ht_entry *del_entry;
	uint8_t ttl;
	
	del_entry = hashtable->entries[hash];

	/* let's store it in a variable */
	ttl = del_entry->ttl;

	/* free the memory */
	kfree(del_entry);

	/* set the entry to NULL */
	hashtable->entries[hash] = NULL;

	return ttl;
}

/* a small function that prints the table upon exiting the module */
void print_table(hashtable_t *hashtable){

	int i;
	ht_entry *read_entry;

	for(i=0; i<TABLE_SIZE; i++){

		if (hashtable->entries[i] != NULL){

			read_entry = hashtable->entries[i];
			printk(KERN_INFO "Flow ID [%d] - TTL: [%d]", i, read_entry->ttl);

			/* let's also do some clean-up */ 
			kfree(read_entry);
			hashtable->entries[i] = NULL;
		}
	}
	/* free all entries */
	kfree(hashtable->entries);
}

uint8_t allocate_ttl_for_flow(int hash, hashtable_t *hashtable){

	uint8_t ttl_value;

	/* add to the table */
	add_flow_to_table(hash, hashtable);

	/* return the ttl that we have saved */
	ttl_value = hashtable->entries[hash]->ttl;

	return ttl_value;

}            

/* -------------- this part takes care of the bit calculations ---------------- */


void print_bits(void){

	int i;
	ht_entry *entry;

	for(i=0; i<TABLE_SIZE; i++){

		entry = hashtable_udp->entries[i];
		
		if(entry!=NULL){
			if(entry->is_active == 1){
			printk(KERN_INFO "Flow [%d] bit is set", i);
			}
		}
	}
}


/* -------------- this part takes care of the timer/ageing time ---------------- */ 

/* initialize the variables */
int aging_time; /* in msecs */
struct timer_list age_timer;

/* let's track the funtion of the timer with a variable
	if it's 0 then we reset the bits, if it's 1 we clean up unused flows */  
int timer_tracker;

/* set up the ageing time */
static void timer_handler(struct timer_list *timer){

	/*Restart the timer each time the function is called*/
    mod_timer(&age_timer, jiffies + msecs_to_jiffies(aging_time/2));

	int i; 
	int count;
	ht_entry *entry;
 
	/* let's check what situation we are in */
	if (timer_tracker==0){

		count = 0;
		/* at half of the ageing time set all bits to zero */
		/* zero all the bits */
		for(i=0; i<TABLE_SIZE; i++){
			entry = hashtable_udp->entries[i];
			if(entry!=NULL){
				entry->is_active = 0;
				count++;
				} 
		}
		/* change the timer_tracker */
		timer_tracker = 1;
		printk(KERN_INFO "%d active bits reset", count);
	}else{
		count = 0;
		/* delete all flows that have the set_bit 0 */
		for(i=0; i<TABLE_SIZE; i++){

			if (hashtable_udp->entries[i] != NULL){
				if(ACTIVE_BIT_NOT_SET(i, hashtable_udp)){
					delete_flow_id(i, hashtable_udp);
					count++;
				} 
			}
		}
		/* change the timer_tracker */
		timer_tracker = 0;
		printk(KERN_INFO "%d UDP flows deleted!", count);
	}	
}


/* ---------------------- setup ends here ---------------------- */
	
int change_ttl_tcp(struct sk_buff *skb, struct iphdr *iph, struct tcphdr *tcp, int hash){

	uint8_t temp;

	/* alocates a random ttl based to the hash */
	iph->ttl = allocate_ttl_for_flow(hash, hashtable_tcp);

	/* VERBOSE: */
	/* printk(KERN_INFO "TCP | Hash: %d TTL: %d", hash, iph->ttl); */

	/* recalculate the checksum for the ip header */
	iph->check = 0;
	iph->check = ip_fast_csum(iph, iph->ihl);

	/* based on a macro defined in the compiler header, we can predict which case is more likely,
	   we know that most packets will not have the fin flag set */ 
	if(unlikely(tcp_flag_word(tcp) & TCP_FLAG_FIN)){

		/* free the memory, goodbye flow! */
		temp = delete_flow_id(hash, hashtable_tcp);
		printk(KERN_INFO "--> DELETED tcp flow ID: %d ttl: %d", hash, temp);
	} 

	return 0;

}

int change_ttl_udp(struct sk_buff *skb, struct iphdr *iph, int hash){


	/* alocates a random ttl based to the hash */
	iph->ttl = allocate_ttl_for_flow(hash, hashtable_udp);

	/* VERBOSE: */
	/* printk(KERN_INFO "UDP | Hash: %d TTL: %d", hash, iph->ttl); */

	/* recalculate the checksum for the ip header */
	iph->check = 0;
	iph->check = ip_fast_csum(iph, iph->ihl);

	return 0;

}

int get_tuple_hash_tcp(struct sk_buff *skb, struct iphdr *iph, struct tcphdr *tcp){

	uint32_t source_ip;
	uint32_t dest_ip;
	uint16_t source_port;
	uint16_t dest_port;
	uint8_t proto_num;
	uint32_t tuple_sum;

	int hash;

	/* manually unpacking the 5-tuple for this particular flow */ 
	source_ip = ntohl(iph->saddr);
	dest_ip = ntohl(iph->daddr);
	source_port = ntohs(tcp->source);
	dest_port = ntohs(tcp->dest);
	proto_num = iph->protocol;

	/* some simple bitwise operations to generate a flow id */
	tuple_sum = ((source_ip | dest_ip) & (source_port | dest_port)) | proto_num;

	/* let's get that hash */
	hash = HASH_FUNC(tuple_sum);

	return hash;

}

int get_tuple_hash_udp(struct sk_buff *skb, struct iphdr *iph, struct udphdr *udp){

	uint32_t source_ip;
	uint32_t dest_ip;
	uint16_t source_port;
	uint16_t dest_port;
	uint8_t proto_num;
	uint32_t tuple_sum;

	int hash;

	/* manually unpacking the 5-tuple */ 
	source_ip = ntohl(iph->saddr);
	dest_ip = ntohl(iph->daddr);
	source_port = ntohs(udp->source);
	dest_port = ntohs(udp->dest);
	proto_num = iph->protocol;

	/* some simple bitwise operations to generate a flow id */
	tuple_sum = ((source_ip | dest_ip) & (source_port | dest_port)) | proto_num;

	/* let's get that hash */
	hash = HASH_FUNC(tuple_sum);

	return hash;

}

static unsigned int hfunc_out(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct iphdr *iph;
	struct tcphdr *tcp;

	int hash;
	
	if (!skb)
		return NF_ACCEPT;
	iph = ip_hdr(skb);
	tcp = tcp_hdr(skb);

	hash = get_tuple_hash_tcp(skb, iph, tcp);

	switch(iph->protocol)
	{
		/* ICMP for debugging purposes: */

		/case IPPROTO_ICMP:
			/* change_ttl_tcp(skb, iph, tcp, hash); */
			return NF_ACCEPT;
 
		case IPPROTO_TCP:
			change_ttl_tcp(skb, iph, tcp, hash);	
			return NF_ACCEPT;

		case IPPROTO_UDP:
			return NF_ACCEPT;
	}

	printk(KERN_INFO "The packet is corrupt!");
	return NF_DROP;
}

/* only changes the ttl for incoming UDP packets */
static unsigned int hfunc_in(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct iphdr *iph;
	/* struct tcphdr *tcp; */
	struct udphdr *udp;

	int hash;
	
	if (!skb)
		return NF_ACCEPT;

	iph = ip_hdr(skb);
	/* tcp = tcp_hdr(skb); */
	udp = udp_hdr(skb);

	hash = get_tuple_hash_udp(skb, iph, udp);

	switch(iph->protocol)
	{
		case IPPROTO_ICMP:
			return NF_ACCEPT;
 
		case IPPROTO_TCP:
			return NF_ACCEPT;

		/* change the ttl of incoming UDP packets */
		case IPPROTO_UDP:
			change_ttl_udp(skb, iph, hash);
			return NF_ACCEPT;
	}

	printk(KERN_INFO "The packet is corrupt!");
	return NF_DROP;
}

static int __init LKM_init(void)
{
	hook_out = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
	hook_in = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);

	/* this is a good place to initialize the hash table for our flow_id's and ttl's */
	init_hash_tables();

	/* a good place to initialize the global timer that will clean up UDP flows */
	aging_time = 1000 * 60; // one minute
	timer_tracker = 0;

	/* sets up the timer */
	timer_setup(&age_timer, timer_handler, 0);

	/* restarts the timer */
    mod_timer(&age_timer, jiffies + msecs_to_jiffies(aging_time/2));

    if (hook_out == NULL) {return -1;}
	if (hook_in == NULL) {return -1;}
	
	/* Initialize netfilter out hook */
	hook_out->hook 	    = (nf_hookfn*)hfunc_out;	/* hook function */
	hook_out->hooknum 	= NF_INET_POST_ROUTING;		/* outgoing packets */
	hook_out->pf 	    = PF_INET;					/* IPv4 */
	hook_out->priority 	= NF_IP_PRI_FIRST;			/* max hook priority */
	
	nf_register_net_hook(&init_net, hook_out);


	/* we shouldn't define the pre hook yet, without writing a function just for it */
	hook_in->hook 	    = (nf_hookfn*)hfunc_in;		
	hook_in->hooknum 	= NF_INET_PRE_ROUTING;		
	hook_in->pf 	    = PF_INET;					
	hook_in->priority 	= NF_IP_PRI_FIRST;			
	

	nf_register_net_hook(&init_net, hook_in);

	printk(KERN_INFO "The hook module function loaded to the kernel!\n");
    return 0;

}

static void __exit LKM_exit(void)
{

	/* prints all the hashtables and frees the memory */ 

	printk(KERN_INFO "---------SET BITS (ACTIVE UDP FLOWS)------");
	print_bits();

	printk(KERN_INFO "-------------TCP HASHTABLE----------------");
	print_table(hashtable_tcp);
	kfree(hashtable_tcp);

	printk(KERN_INFO "-------------UDP HASHTABLE----------------");
	print_table(hashtable_udp);
	kfree(hashtable_udp);


	/* clean up the timer */
	del_timer(&age_timer);

	/* clean-up the hook */ 
	nf_unregister_net_hook(&init_net, hook_out);
	kfree(hook_out);
	printk(KERN_INFO "...The hook module is GONE from the kernel!");
}

module_init(LKM_init);
module_exit(LKM_exit);
