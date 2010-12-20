#include <stdlib.h>
#include <stdio.h>
#include <junkie/proto/proto.h>
#include <junkie/cpp.h>

// Default parse continuation :
static void dump_frame_rec(struct proto_layer const *layer)
{
    if (layer->parent) dump_frame_rec(layer->parent);
    printf("%s@%p: %s\n", layer->parser->proto->name, layer->parser, layer->info->ops->to_str(layer->info));
}

int parse_callback(struct proto_layer *last)
{
    dump_frame_rec(last);
    printf("\n");
    return 0;
}

void on_load(void)
{
	SLOG(LOG_INFO, "Dumper loaded\n");
}

void on_unload(void)
{
	SLOG(LOG_INFO, "Dumper unloading\n");
}
