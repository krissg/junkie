// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
/* Copyright 2010, SecurActive.
 *
 * This file is part of Junkie.
 *
 * Junkie is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Junkie is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with Junkie.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <ltdl.h>
#include <junkie/tools/log.h>
#include <junkie/tools/mallocer.h>
#include <junkie/ext.h>
#include "plugins.h"

static char const Id[] = "$Id: f64d604a02d098feec7f6f1ad4a7f3a641107ac4 $";

struct mutex plugins_mutex;

struct plugins plugins = LIST_HEAD_INITIALIZER(&plugins);

static int plugin_ctor(struct plugin *plugin, char const *libname)
{
    mutex_lock(&plugins_mutex);
    plugin->handle = lt_dlopen(libname);
    if (! plugin->handle) {
        mutex_unlock(&plugins_mutex);
        SLOG(LOG_CRIT, "Cannot load plugin %s : %s", libname, lt_dlerror());
        return -1;
    }
    snprintf(plugin->libname, sizeof(plugin->libname), "%s", libname);
    plugin->parse_callback = lt_dlsym(plugin->handle, "parse_callback");
    SLOG(LOG_DEBUG, "Plugin %s loaded with%s parse callback", libname, plugin->parse_callback ? "":"out");

    // Call the plugin initializer
    void (*on_load)(void) = lt_dlsym(plugin->handle, "on_load");
    if (on_load) on_load();

    LIST_INSERT_HEAD(&plugins, plugin, entry);
    mutex_unlock(&plugins_mutex);
    ext_rebind();
    return 0;
}

static struct plugin *plugin_new(char const *libname)
{
    MALLOCER(plugin);
    struct plugin *plugin = MALLOC(plugin, sizeof(*plugin));
    if (! plugin) return NULL;
    if (0 != plugin_ctor(plugin, libname)) {
        FREE(plugin);
        return NULL;
    }
    return plugin;
}

static void plugin_dtor(struct plugin *plugin)
{
    SLOG(LOG_DEBUG, "Unloading plugin %s", plugin->libname);
    LIST_REMOVE(plugin, entry);

    // Call the plugin finalizer
    void (*on_unload)(void) = lt_dlsym(plugin->handle, "on_unload");
    if (on_unload) on_unload();

    int err = lt_dlclose(plugin->handle);
    if (err) SLOG(LOG_ERR, "Cannot unload plugin %s : %s", plugin->libname, lt_dlerror());
}

static void plugin_del(struct plugin *plugin)
{
    plugin_dtor(plugin);
    FREE(plugin);
}

void plugin_del_all(void)
{
    SLOG(LOG_DEBUG, "Unloading all plugins");

    struct plugin *plugin;
    while (NULL != (plugin = LIST_FIRST(&plugins))) {
        plugin_del(plugin);
    }
}

static struct ext_function sg_load_plugin;
static SCM g_load_plugin(SCM filename)
{
    struct plugin *plugin = plugin_new(scm_to_tempstr(filename));
    return plugin ? SCM_BOOL_T:SCM_BOOL_F;
}

static struct plugin *plugin_lookup(char const *libname)
{
    struct plugin *plugin;
    mutex_lock(&plugins_mutex);
    LIST_FOREACH(plugin, &plugins, entry) {
        if (0 == strcmp(libname, plugin->libname)) return plugin;
    }
    mutex_unlock(&plugins_mutex);
    return NULL;
}

static struct ext_function sg_unload_plugin;
static SCM g_unload_plugin(SCM filename)
{
    struct plugin *plugin = plugin_lookup(scm_to_tempstr(filename));
    if (! plugin) return SCM_BOOL_F;

    plugin_del(plugin);
    return SCM_BOOL_T;
}

static struct ext_function sg_plugins;
static SCM g_plugins(void)
{
    SCM ret = SCM_EOL;
    struct plugin *plugin;
    mutex_lock(&plugins_mutex);
    LIST_FOREACH(plugin, &plugins, entry) {
        ret = scm_cons(scm_from_locale_string(plugin->libname), ret);
    }
    mutex_unlock(&plugins_mutex);
    return ret;
}

void plugins_init(void)
{
    if (0 != lt_dlinit()) {
        DIE("Cannot init ltdl: %s", lt_dlerror());
    }
    mutex_ctor(&plugins_mutex, "plugins");

    ext_function_ctor(&sg_load_plugin,
        "load-plugin", 1, 0, 0, g_load_plugin,
        "(load-plugin \"path/to/libplugin.so\") : load the given plugin into junkie\n"
        "Returns false if the load failed.");

    ext_function_ctor(&sg_unload_plugin,
        "unload-plugin", 1, 0, 0, g_unload_plugin,
        "(unload-plugin \"path/to/libplugin.so\") : unload the give plugin from junkie\n"
        "Returns false if the unload failed.");

    ext_function_ctor(&sg_plugins,
        "plugins", 0, 0, 0, g_plugins,
        "(plugins) : returns a list of loaded plugins");
}

void plugins_fini(void)
{
    lt_dlexit();
}
