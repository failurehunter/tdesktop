/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "window/notifications_manager_default.h"

#include "platform/platform_notifications_manager.h"
#include "platform/platform_specific.h"
#include "core/application.h"
#include "core/ui_integration.h"
#include "chat_helpers/message_field.h"
#include "lang/lang_keys.h"
#include "ui/widgets/buttons.h"
#include "ui/widgets/fields/input_field.h"
#include "ui/platform/ui_platform_utility.h"
#include "ui/text/text_options.h"
#include "ui/text/text_utilities.h"
#include "ui/emoji_config.h"
#include "ui/empty_userpic.h"
#include "ui/painter.h"
#include "ui/power_saving.h"
#include "ui/ui_utility.h"
#include "data/data_premium_limits.h"
#include "data/data_saved_sublist.h"
#include "data/data_session.h"
#include "data/data_forum_topic.h"
#include "data/stickers/data_custom_emoji.h"
#include "dialogs/ui/dialogs_layout.h"
#include "window/window_controller.h"
#include "storage/file_download.h"
#include "main/main_session.h"
#include "main/main_account.h"
#include "history/history.h"
#include "history/history_item.h"
#include "history/view/history_view_item_preview.h"
#include "base/platform/base_platform_last_input.h"
#include "base/call_delayed.h"
#include "base/debug_log.h"
#include "styles/style_dialogs.h"
#include "styles/style_layers.h"
#include "styles/style_window.h"

#include <QtGui/QGuiApplication>
#include <QtGui/QScreen>
#include <QtGui/QMouseEvent>
#include <QtGui/QEnterEvent>
#include <QTimer>
#include <QEventLoop>

#if defined QT_FEATURE_wayland && QT_CONFIG(wayland)
#include "base/platform/linux/base_linux_library.h"

#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>

extern "C" {

typedef int32_t wl_fixed_t;
struct wl_object;
struct wl_array;
struct wl_proxy;
struct wl_display;
struct wl_registry;
struct wl_seat;
struct wl_pointer;
struct wl_surface;
struct wl_compositor;
struct wl_shm;
struct wl_shm_pool;
struct wl_buffer;
struct wl_callback;
struct zwlr_layer_shell_v1;
struct zwlr_layer_surface_v1;

union wl_argument {
	int32_t i;
	uint32_t u;
	wl_fixed_t f;
	const char *s;
	struct wl_object *o;
	uint32_t n;
	struct wl_array *a;
	int32_t h;
};

struct wl_message {
	const char *name;
	const char *signature;
	const struct wl_interface **types;
};

struct wl_interface {
	const char *name;
	int version;
	int method_count;
	const struct wl_message *methods;
	int event_count;
	const struct wl_message *events;
};

struct wl_registry_listener {
	void (*global)(
		void *data,
		struct wl_registry *registry,
		uint32_t name,
		const char *interface,
		uint32_t version);
	void (*global_remove)(
		void *data,
		struct wl_registry *registry,
		uint32_t name);
};

struct wl_seat_listener {
	void (*capabilities)(void *data, struct wl_seat *seat, uint32_t capabilities);
	void (*name)(void *data, struct wl_seat *seat, const char *name);
};

struct wl_callback_listener {
	void (*done)(void *data, struct wl_callback *callback, uint32_t callback_data);
};

struct wl_pointer_listener {
	void (*enter)(void *data, struct wl_pointer *pointer, uint32_t serial, struct wl_surface *surface, wl_fixed_t surface_x, wl_fixed_t surface_y);
	void (*leave)(void *data, struct wl_pointer *pointer, uint32_t serial, struct wl_surface *surface);
	void (*motion)(void *data, struct wl_pointer *pointer, uint32_t time, wl_fixed_t surface_x, wl_fixed_t surface_y);
	void (*button)(void *data, struct wl_pointer *pointer, uint32_t serial, uint32_t time, uint32_t button, uint32_t state);
	void (*axis)(void *data, struct wl_pointer *pointer, uint32_t time, uint32_t axis, wl_fixed_t value);
};

}

namespace WaylandNotifLayer {

const auto kCallbackDoneMessage = wl_message{ "done", "u", nullptr };
const auto kCallbackInterface = wl_interface{
	"wl_callback",
	1,
	0,
	nullptr,
	1,
	&kCallbackDoneMessage,
};

const auto kLayerShellInterface = wl_interface{
	"zwlr_layer_shell_v1",
	4,
	0,
	nullptr,
	0,
	nullptr,
};

const auto kLayerSurfaceRequests = std::array{
	wl_message{ "ack_configure", "u", nullptr },
	wl_message{ "destroy", "", nullptr },
	wl_message{ "set_size", "ii", nullptr },
	wl_message{ "set_anchor", "u", nullptr },
	wl_message{ "set_exclusive_zone", "i", nullptr },
	wl_message{ "set_keyboard_interactivity", "u", nullptr },
	wl_message{ "get_popup", "o", nullptr },
	wl_message{ "set_margin", "iiii", nullptr },
	wl_message{ "set_name", "s", nullptr },
	wl_message{ "set_namespace", "s", nullptr },
};
const auto kLayerSurfaceConfigureEvents = std::array{
	wl_message{ "configure", "uuu", nullptr },
};
const auto kLayerSurfaceInterface = wl_interface{
	"zwlr_layer_surface_v1",
	1,
	int(kLayerSurfaceRequests.size()),
	kLayerSurfaceRequests.data(),
	int(kLayerSurfaceConfigureEvents.size()),
	kLayerSurfaceConfigureEvents.data(),
};

const auto kShmCreatePoolMessage = wl_message{ "create_pool", "nhi", nullptr };
const auto kShmInterface = wl_interface{
	"wl_shm",
	1,
	1,
	&kShmCreatePoolMessage,
	0,
	nullptr,
};
const auto kShmPoolInterface = wl_interface{
	"wl_shm_pool",
	1,
	3,
	std::array{
		wl_message{ "create_buffer", "niiiiu", nullptr },
		wl_message{ "destroy", "", nullptr },
		wl_message{ "resize", "i", nullptr },
	}.data(),
	0,
	nullptr,
};

const auto kSurfaceRequests = std::array{
	wl_message{ "destroy", "", nullptr },
	wl_message{ "attach", "oii", nullptr },
	wl_message{ "damage", "iiii", nullptr },
	wl_message{ "frame", "n", nullptr },
	wl_message{ "set_opaque_region", "?o", nullptr },
	wl_message{ "set_input_region", "?o", nullptr },
	wl_message{ "commit", "", nullptr },
	wl_message{ "set_buffer_transform", "i", nullptr },
	wl_message{ "set_buffer_scale", "i", nullptr },
	wl_message{ "damage_buffer", "iiii", nullptr },
	wl_message{ "offset", "ii", nullptr },
	wl_message{ "set_buffer_release", "i", nullptr },
};
const auto kSurfaceInterface = wl_interface{
	"wl_surface",
	6,
	int(kSurfaceRequests.size()),
	kSurfaceRequests.data(),
	0,
	nullptr,
};

const auto kBufferRequests = std::array{
	wl_message{ "destroy", "", nullptr },
};
const auto kBufferReleaseEvents = std::array{
	wl_message{ "release", "", nullptr },
};
const auto kBufferInterface = wl_interface{
	"wl_buffer",
	1,
	int(kBufferRequests.size()),
	kBufferRequests.data(),
	int(kBufferReleaseEvents.size()),
	kBufferReleaseEvents.data(),
};

const auto kCompositorCreateSurfaceMessage = wl_message{ "create_surface", "n", nullptr };
const auto kCompositorInterface = wl_interface{
	"wl_compositor",
	6,
	1,
	&kCompositorCreateSurfaceMessage,
	0,
	nullptr,
};

const auto kSeatEvents = std::array{
	wl_message{ "capabilities", "u", nullptr },
	wl_message{ "name", "s", nullptr },
};
const auto kSeatInterface = wl_interface{
	"wl_seat",
	5,
	0,
	nullptr,
	int(kSeatEvents.size()),
	kSeatEvents.data(),
};

const auto kPointerEvents = std::array{
	wl_message{ "enter", "uoff", nullptr },
	wl_message{ "leave", "uo", nullptr },
	wl_message{ "motion", "uff", nullptr },
	wl_message{ "button", "uuuu", nullptr },
	wl_message{ "axis", "uuf", nullptr },
};
const auto kPointerInterface = wl_interface{
	"wl_pointer",
	1,
	0,
	nullptr,
	int(kPointerEvents.size()),
	kPointerEvents.data(),
};

struct WaylandSymbols {
	wl_proxy* (*proxyMarshalFlags)(
		wl_proxy*, uint32_t, const wl_interface*,
		uint32_t, uint32_t, ...) = nullptr;
	int (*proxyAddListener)(
		wl_proxy*, void (**)(void), void*) = nullptr;
	void (*proxyDestroy)(wl_proxy*) = nullptr;
	uint32_t (*proxyGetVersion)(wl_proxy*) = nullptr;
	int (*displayFlush)(wl_display*) = nullptr;
	const wl_interface *registryInterface = nullptr;

	[[nodiscard]] explicit operator bool() const {
		return proxyMarshalFlags
			&& proxyAddListener
			&& proxyDestroy
			&& proxyGetVersion
			&& displayFlush
			&& registryInterface;
	}
};

[[nodiscard]] const WaylandSymbols &Wayland() {
	static const auto result = [] {
		auto result = WaylandSymbols{};
		if (const auto lib = base::Platform::LoadLibrary(
				"libwayland-client.so.0",
				RTLD_NODELETE)) {
			base::Platform::LoadSymbol(lib, "wl_proxy_marshal_flags", result.proxyMarshalFlags);
			base::Platform::LoadSymbol(lib, "wl_proxy_add_listener", result.proxyAddListener);
			base::Platform::LoadSymbol(lib, "wl_proxy_destroy", result.proxyDestroy);
			base::Platform::LoadSymbol(lib, "wl_proxy_get_version", result.proxyGetVersion);
			base::Platform::LoadSymbol(lib, "wl_display_flush", result.displayFlush);
			base::Platform::LoadSymbol(lib, "wl_registry_interface", result.registryInterface);
		}
		return result;
	}();
	return result;
}

struct PointerEvent {
	enum class Type {
		Enter,
		Leave,
		Move,
		Press,
		Release,
	};
	Type type = Type::Move;
	QPoint position;
	Qt::MouseButton button = Qt::NoButton;
};

class LayerSurface final {
public:
	LayerSurface() = default;
	LayerSurface(const LayerSurface &) = delete;
	LayerSurface &operator=(const LayerSurface &) = delete;
	~LayerSurface() {
		destroy();
	}

	void setOnPointer(Fn<void(PointerEvent)> callback) {
		_onPointer = std::move(callback);
	}

	void create() {
		if (_registry || _layerSurface) {
			return;
		}
		using namespace QNativeInterface;
		using namespace QNativeInterface::Private;
		const auto wayland = &Wayland();
		if (!*wayland) {
			return;
		}
		const auto native = qApp->nativeInterface<QWaylandApplication>();
		if (!native) {
			return;
		}
		const auto display = native->display();
		if (!display) {
			return;
		}
		_display = display;

		const auto displayProxy = reinterpret_cast<wl_proxy*>(display);
		_registry = wayland->proxyMarshalFlags(
			displayProxy,
			1,
			wayland->registryInterface,
			wayland->proxyGetVersion(displayProxy),
			0,
			nullptr);
		if (!_registry) {
			return;
		}

		wayland->proxyAddListener(
			_registry,
			reinterpret_cast<void(**)(void)>(&_registryListener),
			this);

		const auto sync = wayland->proxyMarshalFlags(
			displayProxy,
			0, // wl_display_sync
			&kCallbackInterface,
			wayland->proxyGetVersion(displayProxy),
			0,
			nullptr);
		if (!sync) {
			wayland->proxyDestroy(_registry);
			_registry = nullptr;
			return;
		}
		wayland->proxyAddListener(
			reinterpret_cast<wl_proxy*>(sync),
			reinterpret_cast<void(**)(void)>(&_syncListener),
			this);
		_syncCallback = sync;
		wayland->displayFlush(display);
	}

	void setSize(int width, int height) {
		_width = width;
		_height = height;
		if (!_layerSurface) return;
		const auto &wayland = Wayland();
		wayland.proxyMarshalFlags(
			reinterpret_cast<wl_proxy*>(_layerSurface),
			2, // set_size
			nullptr,
			wayland.proxyGetVersion(reinterpret_cast<wl_proxy*>(_layerSurface)),
			0,
			int32_t(width),
			int32_t(height));
	}

	void setMargin(int top, int right, int bottom, int left) {
		if (!_layerSurface) return;
		const auto &wayland = Wayland();
		wayland.proxyMarshalFlags(
			reinterpret_cast<wl_proxy*>(_layerSurface),
			7, // set_margin
			nullptr,
			wayland.proxyGetVersion(reinterpret_cast<wl_proxy*>(_layerSurface)),
			0,
			int32_t(top),
			int32_t(right),
			int32_t(bottom),
			int32_t(left));
	}

	void setAnchor(uint32_t anchor) {
		if (!_layerSurface) return;
		const auto &wayland = Wayland();
		wayland.proxyMarshalFlags(
			reinterpret_cast<wl_proxy*>(_layerSurface),
			3, // set_anchor
			nullptr,
			wayland.proxyGetVersion(reinterpret_cast<wl_proxy*>(_layerSurface)),
			0,
			anchor);
	}

	void setOnConfigured(Fn<void()> callback) {
		_onConfigured = std::move(callback);
	}

	void submit(const QImage &image) {
		if (!_surface || !_layerSurface) return;
		const auto &wayland = Wayland();
		if (!wayland) return;
		if (!_configureReceived) return;

		_scale = image.devicePixelRatio();

		ackConfigure(wayland);

		const auto size = image.sizeInBytes();
		const auto stride = image.bytesPerLine();
		if (size <= 0 || stride <= 0) return;

		const auto fd = memfd_create("telegram-notif-shm", MFD_CLOEXEC);
		if (fd < 0) return;

		if (ftruncate(fd, size) < 0) {
			close(fd);
			return;
		}

		const auto data = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		if (data == MAP_FAILED) {
			close(fd);
			return;
		}

		const auto pool = wayland.proxyMarshalFlags(
			reinterpret_cast<wl_proxy*>(_shm),
			0, // wl_shm.create_pool
			&kShmPoolInterface,
			kShmPoolInterface.version,
			0,
			int32_t(fd),
			int32_t(size),
			nullptr);
		if (!pool) {
			munmap(data, size);
			close(fd);
			return;
		}

		const auto buffer = wayland.proxyMarshalFlags(
			reinterpret_cast<wl_proxy*>(pool),
			0, // wl_shm_pool.create_buffer
			&kBufferInterface,
			kBufferInterface.version,
			0,
			int32_t(0),
			int32_t(image.width()),
			int32_t(image.height()),
			int32_t(stride),
			uint32_t(0), // WL_SHM_FORMAT_ARGB8888
			nullptr);
		wayland.proxyDestroy(reinterpret_cast<wl_proxy*>(pool));
		if (!buffer) {
			munmap(data, size);
			close(fd);
			return;
		}

		std::memcpy(data, image.constBits(), size);
		munmap(data, size);
		close(fd);

		wayland.proxyMarshalFlags(
			reinterpret_cast<wl_proxy*>(_surface),
			1, // wl_surface.attach
			nullptr,
			wayland.proxyGetVersion(reinterpret_cast<wl_proxy*>(_surface)),
			0,
			reinterpret_cast<wl_object*>(buffer),
			int32_t(0),
			int32_t(0),
			nullptr);

		wayland.proxyMarshalFlags(
			reinterpret_cast<wl_proxy*>(_surface),
			9, // wl_surface.damage_buffer
			nullptr,
			wayland.proxyGetVersion(reinterpret_cast<wl_proxy*>(_surface)),
			0,
			int32_t(0),
			int32_t(0),
			int32_t(0x7FFFFFFF),
			int32_t(0x7FFFFFFF),
			nullptr);

		wayland.proxyDestroy(reinterpret_cast<wl_proxy*>(buffer));
		commit();
	}

	void commit() {
		if (!_surface) return;
		const auto &wayland = Wayland();
		wayland.proxyMarshalFlags(
			reinterpret_cast<wl_proxy*>(_surface),
			6, // wl_surface.commit
			nullptr,
			wayland.proxyGetVersion(reinterpret_cast<wl_proxy*>(_surface)),
			0);
		if (_display) {
			wayland.displayFlush(_display);
		}
	}

	void destroy() {
		const auto &wayland = Wayland();
		if (wayland) {
			if (_syncCallback) {
				wayland.proxyDestroy(
					reinterpret_cast<wl_proxy*>(_syncCallback));
			}
			if (_registry) {
				wayland.proxyDestroy(_registry);
			}
			if (_pointer) {
				wayland.proxyDestroy(
					reinterpret_cast<wl_proxy*>(_pointer));
			}
			if (_layerSurface) {
				wayland.proxyDestroy(
					reinterpret_cast<wl_proxy*>(_layerSurface));
			}
			if (_surface) {
				wayland.proxyDestroy(
					reinterpret_cast<wl_proxy*>(_surface));
			}
			if (_shell) {
				wayland.proxyDestroy(
					reinterpret_cast<wl_proxy*>(_shell));
			}
			if (_shm) {
				wayland.proxyDestroy(
					reinterpret_cast<wl_proxy*>(_shm));
			}
			if (_compositor) {
				wayland.proxyDestroy(
					reinterpret_cast<wl_proxy*>(_compositor));
			}
			if (_seat) {
				wayland.proxyDestroy(
					reinterpret_cast<wl_proxy*>(_seat));
			}
		}
		_syncCallback = nullptr;
		_registry = nullptr;
		_pointer = nullptr;
		_layerSurface = nullptr;
		_surface = nullptr;
		_shell = nullptr;
		_shm = nullptr;
		_compositor = nullptr;
		_seat = nullptr;
		_configureSerial = 0;
		_display = nullptr;
	}

	[[nodiscard]] bool isValid() const {
		return _layerSurface != nullptr;
	}

private:
	void onRegistryGlobal(
			uint32_t name,
			const char *interface,
			uint32_t) {
		if (!interface) return;
		if (!std::strcmp(interface, "wl_compositor")) {
			_compositorName = name;
		} else if (!std::strcmp(interface, "wl_shm")) {
			_shmName = name;
		} else if (!std::strcmp(interface, "zwlr_layer_shell_v1")) {
			_shellName = name;
		} else if (!std::strcmp(interface, "wl_seat")) {
			_seatName = name;
		}
	}

	void onSyncDone() {
		_syncCallback = nullptr;

		if (!_registry) {
			return;
		}

		if (!_compositorName || !_shmName || !_shellName) {
			destroy();
			return;
		}

		const auto &wayland = Wayland();
		if (!wayland) {
			destroy();
			return;
		}

		const auto bind = [&](uint32_t name, const wl_interface *iface) {
			return wayland.proxyMarshalFlags(
				_registry,
				0, // wl_registry_bind
				iface,
				iface->version,
				0,
				name,
				iface->name,
				iface->version,
				nullptr);
		};

		_compositor = bind(_compositorName, &kCompositorInterface);
		_shm = bind(_shmName, &kShmInterface);
		_shell = bind(_shellName, &kLayerShellInterface);
		if (_seatName) {
			_seat = bind(_seatName, &kSeatInterface);
		}
		wayland.proxyDestroy(_registry);
		_registry = nullptr;

		if (!_compositor || !_shm || !_shell) {
			destroy();
			return;
		}

		_surface = wayland.proxyMarshalFlags(
			reinterpret_cast<wl_proxy*>(_compositor),
			0, // wl_compositor.create_surface
			&kSurfaceInterface,
			kSurfaceInterface.version,
			0,
			nullptr);
		if (!_surface) {
			destroy();
			return;
		}

		// The buffer is prepared at the device pixel ratio, so tell the
		// compositor to scale it back to logical size.
		wayland.proxyMarshalFlags(
			reinterpret_cast<wl_proxy*>(_surface),
			8, // wl_surface.set_buffer_scale
			nullptr,
			wayland.proxyGetVersion(
				reinterpret_cast<wl_proxy*>(_surface)),
			0,
			int32_t(style::DevicePixelRatio()));

		_layerSurface = wayland.proxyMarshalFlags(
			reinterpret_cast<wl_proxy*>(_shell),
			0, // zwlr_layer_shell_v1.get_layer_surface
			&kLayerSurfaceInterface,
			kLayerSurfaceInterface.version,
			0,
			_surface,
			nullptr, // output: all outputs
			uint32_t(3), // ZWLR_LAYER_SHELL_V1_LAYER_OVERLAY
			"telegram-notification");
		if (!_layerSurface) {
			destroy();
			return;
		}

		// Keyboard interactivity: ON_DEMAND (2)
		wayland.proxyMarshalFlags(
			reinterpret_cast<wl_proxy*>(_layerSurface),
			5, // set_keyboard_interactivity
			nullptr,
			wayland.proxyGetVersion(
				reinterpret_cast<wl_proxy*>(_layerSurface)),
			0,
			uint32_t(2));

		// Placeholder anchor until the widget applies the configured
		// corner; no content is attached yet, so nothing is visible.
		wayland.proxyMarshalFlags(
			reinterpret_cast<wl_proxy*>(_layerSurface),
			3, // set_anchor
			nullptr,
			wayland.proxyGetVersion(
				reinterpret_cast<wl_proxy*>(_layerSurface)),
			0,
			uint32_t(0));

		// Exclusive zone: 0 (don't reserve space)
		wayland.proxyMarshalFlags(
			reinterpret_cast<wl_proxy*>(_layerSurface),
			4, // set_exclusive_zone
			nullptr,
			wayland.proxyGetVersion(
				reinterpret_cast<wl_proxy*>(_layerSurface)),
			0,
			int32_t(0));

		// Listen for configure events
		struct LSListener {
			void (*configure)(
				void*,
				void*,
				uint32_t,
				uint32_t,
				uint32_t);
		};
		auto lsListener = LSListener{
			[](void *data, void *, uint32_t serial, uint32_t, uint32_t) {
				static_cast<LayerSurface*>(data)->onConfigure(serial);
			},
		};
		wayland.proxyAddListener(
			reinterpret_cast<wl_proxy*>(_layerSurface),
			reinterpret_cast<void(**)(void)>(&lsListener),
			this);

		// Listen for seat capabilities (for pointer)
		if (_seat) {
			auto seatListener = wl_seat_listener{
				[](void *data, struct wl_seat *, uint32_t caps) {
					static_cast<LayerSurface*>(data)->onSeatCapabilities(
						caps);
				},
				[](void *, struct wl_seat *, const char *) {},
			};
			wayland.proxyAddListener(
				reinterpret_cast<wl_proxy*>(_seat),
				reinterpret_cast<void(**)(void)>(&seatListener),
				this);
		}

		commit();
	}

	void onConfigure(uint32_t serial) {
		_configureSerial = serial;
		if (!_configureReceived) {
			_configureReceived = true;
			if (_onConfigured) {
				_onConfigured();
			}
		}
	}

	void onSeatCapabilities(uint32_t capabilities) {
		// ponytail: only handle pointer (bit 1), skip keyboard/touch
		if (!(capabilities & 1) || _pointer) return;
		const auto &wayland = Wayland();
		if (!wayland || !_seat) return;

		_pointer = wayland.proxyMarshalFlags(
			reinterpret_cast<wl_proxy*>(_seat),
			0, // wl_seat.get_pointer
			&kPointerInterface,
			kPointerInterface.version,
			0,
			nullptr);
		if (!_pointer) return;

		auto pointerListener = wl_pointer_listener{
			[](void *data, struct wl_pointer *, uint32_t,
				struct wl_surface *, wl_fixed_t x, wl_fixed_t y) {
				auto self = static_cast<LayerSurface*>(data);
				if (self->_onPointer) {
					self->_onPointer(PointerEvent{
						.type = PointerEvent::Type::Enter,
						.position = self->surfaceToWidget(x, y),
					});
				}
			},
			[](void *data, struct wl_pointer *, uint32_t,
				struct wl_surface *) {
				auto self = static_cast<LayerSurface*>(data);
				if (self->_onPointer) {
					self->_onPointer(PointerEvent{
						.type = PointerEvent::Type::Leave,
					});
				}
			},
			[](void *data, struct wl_pointer *, uint32_t,
				wl_fixed_t x, wl_fixed_t y) {
				auto self = static_cast<LayerSurface*>(data);
				if (self->_onPointer) {
					self->_onPointer(PointerEvent{
						.type = PointerEvent::Type::Move,
						.position = self->surfaceToWidget(x, y),
					});
				}
			},
			[](void *data, struct wl_pointer *, uint32_t,
				uint32_t, uint32_t button, uint32_t state) {
				auto self = static_cast<LayerSurface*>(data);
				if (!self->_onPointer) {
					return;
				}
				const auto mapped = [&]() -> Qt::MouseButton {
					switch (button) {
					case 0x110: return Qt::LeftButton;
					case 0x111: return Qt::RightButton;
					case 0x112: return Qt::MiddleButton;
					}
					return Qt::NoButton;
				}();
				if (mapped != Qt::NoButton) {
					self->_onPointer(PointerEvent{
						.type = (state == 1)
							? PointerEvent::Type::Press
							: PointerEvent::Type::Release,
						.button = mapped,
					});
				}
			},
			[](void *, struct wl_pointer *, uint32_t, uint32_t, wl_fixed_t) {
			},
		};
		wayland.proxyAddListener(
			reinterpret_cast<wl_proxy*>(_pointer),
			reinterpret_cast<void(**)(void)>(&pointerListener),
			this);
		if (_display) {
			wayland.displayFlush(_display);
		}
	}

	void ackConfigure(const WaylandSymbols &wayland) {
		if (!_configureSerial || !_layerSurface) return;
		wayland.proxyMarshalFlags(
			reinterpret_cast<wl_proxy*>(_layerSurface),
			0, // ack_configure
			nullptr,
			wayland.proxyGetVersion(
				reinterpret_cast<wl_proxy*>(_layerSurface)),
			0,
			_configureSerial);
		_configureSerial = 0;
	}

	wl_display *_display = nullptr;
	wl_proxy *_registry = nullptr;
	wl_proxy *_syncCallback = nullptr;

	uint32_t _compositorName = 0;
	uint32_t _shmName = 0;
	uint32_t _shellName = 0;
	uint32_t _seatName = 0;

	void *_compositor = nullptr;
	void *_shm = nullptr;
	void *_shell = nullptr;
	void *_surface = nullptr;
	void *_layerSurface = nullptr;
	void *_seat = nullptr;
	void *_pointer = nullptr;
	uint32_t _configureSerial = 0;
	bool _configureReceived = false;
	int _width = 0;
	int _height = 0;
	float64 _scale = 1.;
	Fn<void(PointerEvent)> _onPointer;
	Fn<void()> _onConfigured;

	[[nodiscard]] QPoint surfaceToWidget(
			wl_fixed_t x,
			wl_fixed_t y) const {
		const auto scale = (_scale > 0.) ? _scale : 1.;
		return QPoint(
			int(x / 256. / scale),
			int(y / 256. / scale));
	}

	static inline auto _registryListener = wl_registry_listener{
		[](void *data, struct wl_registry *, uint32_t name,
			const char *interface, uint32_t version) {
			static_cast<LayerSurface*>(data)->onRegistryGlobal(
				name,
				interface,
				version);
		},
		[](void *, struct wl_registry *, uint32_t) {
		},
	};

	static inline auto _syncListener = wl_callback_listener{
		[](void *data, struct wl_callback *, uint32_t) {
			static_cast<LayerSurface*>(data)->onSyncDone();
		},
	};

};

} // namespace WaylandNotifLayer
#endif // wayland

namespace Window {
namespace Notifications {

[[nodiscard]] bool HasLayerShell() {
#if defined QT_FEATURE_wayland && QT_CONFIG(wayland)
	static auto cached = false;
	static bool known = false;
	if (known) {
		return cached;
	}

	const auto &wayland = WaylandNotifLayer::Wayland();
	if (!wayland) {
		known = true;
		return false;
	}
	using namespace QNativeInterface;
	using namespace QNativeInterface::Private;
	const auto native = qApp->nativeInterface<QWaylandApplication>();
	if (!native) {
		known = true;
		return false;
	}
	const auto display = native->display();
	if (!display) {
		known = true;
		return false;
	}

	struct State {
		bool found = false;
		bool done = false;
	} state;

	const auto displayProxy = reinterpret_cast<wl_proxy*>(display);
	const auto registry = reinterpret_cast<wl_proxy*>(
		wayland.proxyMarshalFlags(
			displayProxy,
			1,
			wayland.registryInterface,
			wayland.proxyGetVersion(displayProxy),
			0,
			nullptr));
	if (!registry) {
		known = true;
		return false;
	}

	auto listener = wl_registry_listener{
		[](void *data, struct wl_registry *, uint32_t,
			const char *interface, uint32_t) {
			if (interface
				&& !std::strcmp(interface, "zwlr_layer_shell_v1")) {
				static_cast<State*>(data)->found = true;
			}
		},
		[](void *, struct wl_registry *, uint32_t) {
		},
	};
	wayland.proxyAddListener(
		registry,
		reinterpret_cast<void(**)(void)>(&listener),
		&state);

	const auto sync = wayland.proxyMarshalFlags(
		displayProxy,
		0, // wl_display_sync
		&WaylandNotifLayer::kCallbackInterface,
		wayland.proxyGetVersion(displayProxy),
		0,
		nullptr);
	if (!sync) {
		wayland.proxyDestroy(registry);
		known = true;
		return false;
	}

	auto syncListener = wl_callback_listener{
		[](void *data, struct wl_callback *, uint32_t) {
			static_cast<State*>(data)->done = true;
		},
	};
	wayland.proxyAddListener(
		reinterpret_cast<wl_proxy*>(sync),
		reinterpret_cast<void(**)(void)>(&syncListener),
		&state);

	// Push the registry + sync requests to the socket immediately.
	// Qt flushes lazily (inside its readEvents), so without this the
	// probe would sit in our buffer until some unrelated event arrives
	// and the 500 ms timeout would fire first.
	wayland.displayFlush(display);

	// Process events through Qt's event loop until sync callback fires.
	// No direct socket I/O — dispatch happens via Qt's QSocketNotifier.
	{
		auto loop = QEventLoop();
		auto timer = QTimer(&loop);
		timer.setSingleShot(true);
		QObject::connect(
			&timer,
			&QTimer::timeout,
			&loop,
			&QEventLoop::quit);
		timer.start(500);

		while (!state.done && timer.isActive()) {
			loop.processEvents(QEventLoop::AllEvents, 50);
		}
	}

	wayland.proxyDestroy(reinterpret_cast<wl_proxy*>(sync));
	wayland.proxyDestroy(registry);

	if (state.done) {
		LOG(("Wayland layer shell detection: %1")
			.arg(state.found ? "available" : "not available"));
		cached = state.found;
		known = true;
	}
	return state.found;
#else
	return false;
#endif
}

namespace Default {
namespace {

[[nodiscard]] QPoint notificationStartPosition() {
	const auto corner = Core::App().settings().notificationsCorner();
	const auto r = NotificationDisplayRect(Core::App().activePrimaryWindow());
	const auto isLeft = Core::Settings::IsLeftCorner(corner);
	const auto isTop = Core::Settings::IsTopCorner(corner);
	const auto x = (isLeft == rtl())
		? (r.x() + r.width() - st::notifyWidth - st::notifyDeltaX)
		: (r.x() + st::notifyDeltaX);
	const auto y = isTop ? r.y() : (r.y() + r.height());
	return QPoint(x, y);
}

internal::Widget::Direction notificationShiftDirection() {
	auto isTop = Core::Settings::IsTopCorner(Core::App().settings().notificationsCorner());
	return isTop ? internal::Widget::Direction::Down : internal::Widget::Direction::Up;
}

} // namespace

std::unique_ptr<Manager> Create(System *system) {
	return std::make_unique<Manager>(system);
}

Manager::Manager(System *system)
: Notifications::Manager(system)
, _inputCheckTimer([=] { checkLastInput(); }) {
	system->settingsChanged(
	) | rpl::on_next([=](ChangeType change) {
		settingsChanged(change);
	}, _lifetime);
}

Manager::QueuedNotification::QueuedNotification(NotificationFields &&fields)
: history(fields.item->history())
, topicRootId(fields.item->topicRootId())
, peer(history->peer)
, reaction(fields.reactionId)
, author(!fields.reactionFrom
	? fields.item->notificationHeader()
	: (fields.reactionFrom != peer)
	? fields.reactionFrom->name()
	: QString())
, item((fields.forwardedCount < 2) ? fields.item.get() : nullptr)
, forwardedCount(fields.forwardedCount)
, fromScheduled(reaction.empty() && (fields.item->out() || peer->isSelf())
	&& fields.item->isFromScheduled()) {
}

QPixmap Manager::hiddenUserpicPlaceholder() const {
	if (_hiddenUserpicPlaceholder.isNull()) {
		const auto ratio = style::DevicePixelRatio();
		_hiddenUserpicPlaceholder = Ui::PixmapFromImage(
			LogoNoMargin().scaled(
				st::notifyPhotoSize * ratio,
				st::notifyPhotoSize * ratio,
				Qt::IgnoreAspectRatio,
				Qt::SmoothTransformation));
		_hiddenUserpicPlaceholder.setDevicePixelRatio(ratio);
	}
	return _hiddenUserpicPlaceholder;
}

bool Manager::hasReplyingNotification() const {
	for (const auto &notification : _notifications) {
		if (notification->isReplying()) {
			return true;
		}
	}
	return false;
}

void Manager::settingsChanged(ChangeType change) {
	if (change == ChangeType::Corner) {
		auto startPosition = notificationStartPosition();
		auto shiftDirection = notificationShiftDirection();
		for (const auto &notification : _notifications) {
			notification->updatePosition(startPosition, shiftDirection);
		}
		if (_hideAll) {
			_hideAll->updatePosition(startPosition, shiftDirection);
		}
	} else if (change == ChangeType::MaxCount) {
		int allow = Core::App().settings().notificationsCount();
		for (int i = _notifications.size(); i != 0;) {
			auto &notification = _notifications[--i];
			if (notification->isUnlinked()) continue;
			if (--allow < 0) {
				notification->unlinkHistory();
			}
		}
		if (allow > 0) {
			for (int i = 0; i != allow; ++i) {
				showNextFromQueue();
			}
		}
	} else if ((change == ChangeType::DemoIsShown)
			|| (change == ChangeType::DemoIsHidden)) {
		_demoIsShown = (change == ChangeType::DemoIsShown);
		_demoMasterOpacity.start(
			[=] { demoMasterOpacityCallback(); },
			_demoIsShown ? 1. : 0.,
			_demoIsShown ? 0. : 1.,
			st::notifyFastAnim);
	}
}

void Manager::demoMasterOpacityCallback() {
	for (const auto &notification : _notifications) {
		notification->updateOpacity();
	}
	if (_hideAll) {
		_hideAll->updateOpacity();
	}
}

float64 Manager::demoMasterOpacity() const {
	return _demoMasterOpacity.value(_demoIsShown ? 0. : 1.);
}

void Manager::checkLastInput() {
	auto replying = hasReplyingNotification();
	auto waiting = false;
	const auto lastInputTime = base::Platform::LastUserInputTimeSupported()
		? std::make_optional(Core::App().lastNonIdleTime())
		: std::nullopt;
	for (const auto &notification : _notifications) {
		if (!notification->checkLastInput(replying, lastInputTime)) {
			waiting = true;
		}
	}
	if (waiting) {
		_inputCheckTimer.callOnce(300);
	}
}

void Manager::startAllHiding() {
	if (!hasReplyingNotification()) {
		for (const auto &notification : _notifications) {
			notification->startHiding();
		}
		if (_hideAll && _queuedNotifications.size() < 2) {
			_hideAll->startHiding();
		}
	}
}

void Manager::stopAllHiding() {
	for (const auto &notification : _notifications) {
		notification->stopHiding();
	}
	if (_hideAll) {
		_hideAll->stopHiding();
	}
}

void Manager::showNextFromQueue() {
	auto guard = gsl::finally([this] {
		if (_positionsOutdated) {
			moveWidgets();
		}
	});
	if (_queuedNotifications.empty()) {
		return;
	}
	int count = Core::App().settings().notificationsCount();
	for (const auto &notification : _notifications) {
		if (notification->isUnlinked()) continue;
		--count;
	}
	if (count <= 0) {
		return;
	}

	auto startPosition = notificationStartPosition();
	auto startShift = 0;
	auto shiftDirection = notificationShiftDirection();
	do {
		auto queued = _queuedNotifications.front();
		_queuedNotifications.pop_front();

		subscribeToSession(&queued.history->session());
		_notifications.push_back(std::make_unique<Notification>(
			this,
			queued.history,
			queued.topicRootId,
			queued.monoforumPeerId,
			queued.peer,
			queued.author,
			queued.item,
			queued.reaction,
			queued.forwardedCount,
			queued.fromScheduled,
			startPosition,
			startShift,
			shiftDirection));
		--count;
	} while (count > 0 && !_queuedNotifications.empty());

	_positionsOutdated = true;
	checkLastInput();
}

void Manager::subscribeToSession(not_null<Main::Session*> session) {
	auto i = _subscriptions.find(session);
	if (i == _subscriptions.end()) {
		i = _subscriptions.emplace(session).first;
		session->account().sessionChanges(
		) | rpl::on_next([=] {
			_subscriptions.remove(session);
		}, i->second.lifetime);
	} else if (i->second.subscription) {
		return;
	}
	session->downloaderTaskFinished(
	) | rpl::on_next([=] {
		auto found = false;
		for (const auto &notification : _notifications) {
			if (const auto history = notification->maybeHistory()) {
				if (&history->session() == session) {
					notification->updatePeerPhoto();
					found = true;
				}
			}
		}
		if (!found) {
			_subscriptions[session].subscription.destroy();
		}
	}, i->second.subscription);
}

void Manager::moveWidgets() {
	auto shift = st::notifyDeltaY;
	int lastShift = 0, lastShiftCurrent = 0, count = 0;
	for (int i = _notifications.size(); i != 0;) {
		auto &notification = _notifications[--i];
		if (notification->isUnlinked()) continue;

		notification->changeShift(shift);
		shift += notification->height() + st::notifyDeltaY;

		lastShiftCurrent = notification->currentShift();
		lastShift = shift;

		++count;
	}

	if (count > 1 || !_queuedNotifications.empty()) {
		if (!_hideAll) {
			_hideAll = std::make_unique<HideAllButton>(this, notificationStartPosition(), lastShiftCurrent, notificationShiftDirection());
		}
		_hideAll->changeShift(lastShift);
		_hideAll->stopHiding();
	} else if (_hideAll) {
		_hideAll->startHidingFast();
	}
}

void Manager::changeNotificationHeight(Notification *notification, int newHeight) {
	auto deltaHeight = newHeight - notification->height();
	if (!deltaHeight) return;

	notification->addToHeight(deltaHeight);
	auto it = std::find_if(_notifications.cbegin(), _notifications.cend(), [notification](auto &item) {
		return (item.get() == notification);
	});
	if (it != _notifications.cend()) {
		for (auto i = _notifications.cbegin(); i != it; ++i) {
			auto &notification = *i;
			if (notification->isUnlinked()) continue;

			notification->addToShift(deltaHeight);
		}
	}
	if (_hideAll) {
		_hideAll->addToShift(deltaHeight);
	}
}

void Manager::unlinkFromShown(Notification *remove) {
	if (remove) {
		if (remove->unlinkHistory()) {
			_positionsOutdated = true;
		}
	}
	showNextFromQueue();
}

void Manager::removeWidget(internal::Widget *remove) {
	if (remove == _hideAll.get()) {
		_hideAll.reset();
	} else if (remove) {
		const auto it = ranges::find(
			_notifications,
			remove,
			&std::unique_ptr<Notification>::get);
		if (it != end(_notifications)) {
			_notifications.erase(it);
			_positionsOutdated = true;
		}
	}
	showNextFromQueue();
}

void Manager::doShowNotification(NotificationFields &&fields) {
	_queuedNotifications.emplace_back(std::move(fields));
	showNextFromQueue();
}

void Manager::doClearAll() {
	_queuedNotifications.clear();
	for (const auto &notification : _notifications) {
		notification->unlinkHistory();
	}
	showNextFromQueue();
}

void Manager::doClearAllFast() {
	_queuedNotifications.clear();
	base::take(_notifications);
	base::take(_hideAll);
}

void Manager::doClearFromTopic(not_null<Data::ForumTopic*> topic) {
	const auto history = topic->history();
	const auto topicRootId = topic->rootId();
	for (auto i = _queuedNotifications.begin(); i != _queuedNotifications.cend();) {
		if (i->history == history && i->topicRootId == topicRootId) {
			i = _queuedNotifications.erase(i);
		} else {
			++i;
		}
	}
	for (const auto &notification : _notifications) {
		if (notification->unlinkHistory(history, topicRootId, PeerId())) {
			_positionsOutdated = true;
		}
	}
	showNextFromQueue();
}

void Manager::doClearFromSublist(not_null<Data::SavedSublist*> sublist) {
	const auto history = sublist->owningHistory();
	const auto sublistPeerId = sublist->sublistPeer()->id;
	for (auto i = _queuedNotifications.begin(); i != _queuedNotifications.cend();) {
		if (i->history == history && i->monoforumPeerId == sublistPeerId) {
			i = _queuedNotifications.erase(i);
		} else {
			++i;
		}
	}
	for (const auto &notification : _notifications) {
		if (notification->unlinkHistory(history, MsgId(), sublistPeerId)) {
			_positionsOutdated = true;
		}
	}
	showNextFromQueue();
}

void Manager::doClearFromHistory(not_null<History*> history) {
	for (auto i = _queuedNotifications.begin(); i != _queuedNotifications.cend();) {
		if (i->history == history) {
			i = _queuedNotifications.erase(i);
		} else {
			++i;
		}
	}
	for (const auto &notification : _notifications) {
		if (notification->unlinkHistory(history)) {
			_positionsOutdated = true;
		}
	}
	showNextFromQueue();
}

void Manager::doClearFromSession(not_null<Main::Session*> session) {
	for (auto i = _queuedNotifications.begin(); i != _queuedNotifications.cend();) {
		if (&i->history->session() == session) {
			i = _queuedNotifications.erase(i);
		} else {
			++i;
		}
	}
	for (const auto &notification : _notifications) {
		if (notification->unlinkSession(session)) {
			_positionsOutdated = true;
		}
	}
	showNextFromQueue();
}

void Manager::doClearFromItem(not_null<HistoryItem*> item) {
	_queuedNotifications.erase(std::remove_if(_queuedNotifications.begin(), _queuedNotifications.end(), [&](auto &queued) {
		return (queued.item == item);
	}), _queuedNotifications.cend());

	auto showNext = false;
	for (const auto &notification : _notifications) {
		if (notification->unlinkItem(item)) {
			showNext = true;
		}
	}
	if (showNext) {
		// This call invalidates _notifications iterators.
		showNextFromQueue();
	}
}

bool Manager::doSkipToast() const {
	return Platform::Notifications::SkipToastForCustom();
}

void Manager::doMaybePlaySound(Fn<void()> playSound) {
	Platform::Notifications::MaybePlaySoundForCustom(std::move(playSound));
}

void Manager::doMaybeFlashBounce(Fn<void()> flashBounce) {
	Platform::Notifications::MaybeFlashBounceForCustom(std::move(flashBounce));
}

void Manager::doUpdateAll() {
	for (const auto &notification : _notifications) {
		notification->updateNotifyDisplay();
	}
}

Manager::~Manager() {
	clearAllFast();
}

namespace internal {

Widget::Widget(
	not_null<Manager*> manager,
	QPoint startPosition,
	int shift,
	Direction shiftDirection)
: _manager(manager)
, _startPosition(startPosition)
, _direction(shiftDirection)
, _shift(shift)
, _shiftAnimation([=](crl::time now) {
	return shiftAnimationCallback(now);
}) {
	setWindowOpacity(0.);

	setWindowFlags(Qt::WindowFlags(Qt::FramelessWindowHint)
		| Qt::WindowStaysOnTopHint
		| Qt::BypassWindowManagerHint
		| Qt::NoDropShadowWindowHint
		| Qt::Tool);
	setAttribute(Qt::WA_MacAlwaysShowToolWindow);
	setAttribute(Qt::WA_OpaquePaintEvent);

	Ui::Platform::InitOnTopPanel(this);

#if defined QT_FEATURE_wayland && QT_CONFIG(wayland)
	if (HasLayerShell()) {
		_layerSurface = std::make_unique<WaylandNotifLayer::LayerSurface>();
		_layerSurface->setOnPointer(
			[this](const WaylandNotifLayer::PointerEvent &event) {
				handleLayerPointer(event);
			});
		// Submit the first frame once the compositor has configured the
		// surface; before that submit() is a no-op and the fade frames
		// of a fresh notification would be lost.
		_layerSurface->setOnConfigured([this] { submitLayerFrame(); });
		InvokeQueued(this, [=] { ensureLayerSurface(); });
	}
#endif

	_a_opacity.start([this] { opacityAnimationCallback(); }, 0., 1., st::notifyFastAnim);
}

void Widget::opacityAnimationCallback() {
	updateOpacity();
	update();
#if defined QT_FEATURE_wayland && QT_CONFIG(wayland)
	submitLayerFrame();
#endif
	if (!_a_opacity.animating() && _hiding) {
		if (underMouse()) {
			// The notification is leaving from under the cursor, but in such case leave hook is not
			// triggered automatically. But we still want the manager to start hiding notifications
			// (see #28813).
			manager()->startAllHiding();
		}
		manager()->removeWidget(this);  // Deletes `this`
	}
}

bool Widget::shiftAnimationCallback(crl::time now) {
	if (anim::Disabled()) {
		now += st::notifyFastAnim;
	}
	const auto dt = (now - _shiftAnimation.started())
		/ float64(st::notifyFastAnim);
	if (dt >= 1.) {
		_shift.finish();
	} else {
		_shift.update(dt, anim::linear);
	}
	moveByShift();
#if defined QT_FEATURE_wayland && QT_CONFIG(wayland)
	submitLayerFrame();
#endif
	return (dt < 1.);
}

void Widget::hideSlow() {
	if (anim::Disabled()) {
		_hiding = true;
		base::call_delayed(
			st::notifySlowHide,
			this,
			[=, guard = _hidingDelayed.make_guard()] {
				if (guard && _hiding) {
					hideFast();
				}
			});
	} else {
		hideAnimated(st::notifySlowHide, anim::easeInCirc);
	}
}

void Widget::hideFast() {
	hideAnimated(st::notifyFastAnim, anim::linear);
}

void Widget::hideStop() {
	if (_hiding) {
		_hiding = false;
		_hidingDelayed = {};
		_a_opacity.start([this] { opacityAnimationCallback(); }, 0., 1., st::notifyFastAnim);
	}
}

void Widget::hideAnimated(float64 duration, const anim::transition &func) {
	_hiding = true;
	// Stop the previous animation so as to make sure that the notification
	// is fully restored before hiding it again.
	// Relates to https://github.com/telegramdesktop/tdesktop/issues/28811.
	_a_opacity.stop();
	_a_opacity.start([this] { opacityAnimationCallback(); }, 1., 0., duration, func);
}

void Widget::updateOpacity() {
#if defined QT_FEATURE_wayland && QT_CONFIG(wayland)
	if (_layerSurface && _layerSurface->isValid()) {
		return;
	}
#endif
	setWindowOpacity(_a_opacity.value(_hiding ? 0. : 1.) * _manager->demoMasterOpacity());
}

void Widget::changeShift(int top) {
	_shift.start(top);
	_shiftAnimation.start();
}

void Widget::updatePosition(QPoint startPosition, Direction shiftDirection) {
	_startPosition = startPosition;
	_direction = shiftDirection;
	moveByShift();
}

void Widget::addToHeight(int add) {
	auto newHeight = height() + add;
	auto newPosition = computePosition(newHeight);
	updateGeometry(newPosition.x(), newPosition.y(), width(), newHeight);
	Ui::ForceFullRepaintSync(this);
}

void Widget::updateGeometry(int x, int y, int width, int height) {
	move(x, y);
	setFixedSize(width, height);
	update();
#if defined QT_FEATURE_wayland && QT_CONFIG(wayland)
	if (_layerSurface && _layerSurface->isValid()) {
		updateLayerGeometry();
		submitLayerFrame();
	}
#endif
}

void Widget::addToShift(int add) {
	_shift.add(add);
	moveByShift();
}

void Widget::moveByShift() {
	const auto pos = computePosition(height());
	move(pos);
#if defined QT_FEATURE_wayland && QT_CONFIG(wayland)
	applyLayerPosition(pos);
#endif
}

QPoint Widget::computePosition(int height) const {
	auto realShift = qRound(_shift.current());
	if (_direction == Direction::Up) {
		realShift = -realShift - height;
	}
	return QPoint(_startPosition.x(), _startPosition.y() + realShift);
}

#if defined QT_FEATURE_wayland && QT_CONFIG(wayland)
void Widget::ensureLayerSurface() {
	if (!_layerSurface || _layerSurface->isValid()) {
		return;
	}
	_layerSurface->create();
	if (_layerSurface->isValid()) {
		hide();
		updateLayerGeometry();
		submitLayerFrame();
	}
}

void Widget::updateLayerGeometry() {
	const auto ratio = style::DevicePixelRatio();
	const auto pos = computePosition(height());
	_layerSurface->setSize(int(width() * ratio), int(height() * ratio));
	applyLayerPosition(pos);
}

void Widget::applyLayerPosition(QPoint pos) {
	if (!_layerSurface || !_layerSurface->isValid()) {
		return;
	}
	// The surface is positioned relative to the configured corner by the
	// anchor bitfield (top/bottom/left/right), with margins as distances
	// from those edges. Anchor NONE would center the surface instead.
	const auto corner = Core::App().settings().notificationsCorner();
	const auto isLeft = Core::Settings::IsLeftCorner(corner);
	const auto isTop = Core::Settings::IsTopCorner(corner);
	const auto leftSide = (isLeft != rtl());
	const auto r = NotificationDisplayRect(Core::App().activePrimaryWindow());
	const auto anchor = (isTop ? 1 : 2) | (leftSide ? 4 : 8);
	const auto topMargin = isTop ? (pos.y() - r.y()) : 0;
	const auto bottomMargin = isTop
		? 0
		: (r.y() + r.height() - (pos.y() + height()));
	const auto leftMargin = leftSide ? (pos.x() - r.x()) : 0;
	const auto rightMargin = leftSide
		? 0
		: (r.x() + r.width() - (pos.x() + width()));
	_layerSurface->setAnchor(anchor);
	_layerSurface->setMargin(topMargin, rightMargin, bottomMargin, leftMargin);
}

void Widget::submitLayerFrame() {
	if (!_layerSurface || !_layerSurface->isValid()) {
		return;
	}
	if (isVisible()) {
		hide();
	}

	const auto ratio = style::DevicePixelRatio();
	const auto imageSize = QSize(width(), height()) * ratio;
	auto image = QImage(imageSize, QImage::Format_ARGB32_Premultiplied);
	image.setDevicePixelRatio(ratio);
	image.fill(Qt::transparent);
	render(&image);

	const auto opacity = _a_opacity.value(_hiding ? 0. : 1.)
		* _manager->demoMasterOpacity();
	if (opacity < 1.) {
		auto painter = QPainter(&image);
		painter.setCompositionMode(
			QPainter::CompositionMode_DestinationIn);
		painter.fillRect(
			image.rect(),
			QColor(0, 0, 0, int(opacity * 255)));
		painter.end();
		// wl_shm has only straight-alpha formats (ARGB8888), so the
		// premultiplied fade frame must be unpremultiplied before the copy.
		image = image.convertToFormat(QImage::Format_ARGB32);
	}

	_layerSurface->submit(image);
}

void Widget::handleLayerPointer(const WaylandNotifLayer::PointerEvent &event) {
	if (!_layerSurface || !_layerSurface->isValid()) {
		return;
	}
	using Type = WaylandNotifLayer::PointerEvent::Type;
	auto reRender = false;
	switch (event.type) {
	case Type::Enter: {
		_layerPointerPosition = event.position;
		enterLayerWidget();
		reRender = true;
	} break;
	case Type::Leave: {
		_layerPointerPosition = event.position;
		leaveLayerWidget();
		_layerPressed = nullptr;
		_layerButtonsState = {};
		reRender = true;
	} break;
	case Type::Move: {
		_layerPointerPosition = event.position;
	} break;
	case Type::Press: {
		_layerPointerPosition = event.position;
		_layerButtonsState |= event.button;
		pressLayerButton(event.button);
		reRender = true;
	} break;
	case Type::Release: {
		_layerPointerPosition = event.position;
		releaseLayerButton(event.button);
		_layerButtonsState &= ~event.button;
		reRender = true;
	} break;
	}
	if (reRender) {
		submitLayerFrame();
	}
}

void Widget::enterLayerWidget() {
	const auto global = mapToGlobal(_layerPointerPosition);
	QEnterEvent enter(
		_layerPointerPosition,
		_layerPointerPosition,
		global);
	QCoreApplication::sendEvent(this, &enter);
}

void Widget::leaveLayerWidget() {
	QEvent leave(QEvent::Leave);
	QCoreApplication::sendEvent(this, &leave);
}

QWidget *Widget::layerChildAt(QWidget *root, QPoint position) const {
	for (auto i = root->children().rbegin();
			i != root->children().rend(); ++i) {
		const auto child = qobject_cast<QWidget*>(*i);
		if (!child
			|| child->isHidden()
			|| !child->geometry().contains(position)) {
			continue;
		}
		const auto local = position - child->pos();
		if (const auto inner = layerChildAt(child, local)) {
			return inner;
		}
		return child;
	}
	return nullptr;
}

QWidget *Widget::layerChildAt(const QPoint &position) const {
	return layerChildAt(const_cast<Widget*>(this), position);
}

void Widget::sendLayerMouse(
		QEvent::Type type,
		Qt::MouseButton button,
		QWidget *target) {
	auto local = _layerPointerPosition;
	for (auto widget = target; widget && widget != this;) {
		local -= widget->pos();
		widget = widget->parentWidget();
	}
	const auto global = mapToGlobal(_layerPointerPosition);
	QMouseEvent event(
		type,
		local,
		local,
		global,
		button,
		_layerButtonsState,
		{});
	QCoreApplication::sendEvent(target, &event);
}

void Widget::pressLayerButton(Qt::MouseButton button) {
	const auto child = layerChildAt(_layerPointerPosition);
	const auto target = child ? child : this;
	_layerPressed = target;
	sendLayerMouse(QEvent::MouseButtonPress, button, target);
}

void Widget::releaseLayerButton(Qt::MouseButton button) {
	const auto target = _layerPressed ? _layerPressed : this;
	_layerPressed = nullptr;
	sendLayerMouse(QEvent::MouseButtonRelease, button, target);
}

bool Widget::layerSurfaceActive() const {
	return _layerSurface && _layerSurface->isValid();
}
#endif

Background::Background(QWidget *parent) : RpWidget(parent) {
	setAttribute(Qt::WA_OpaquePaintEvent);
}

void Background::paintEvent(QPaintEvent *e) {
	Painter p(this);

	p.fillRect(rect(), st::notificationBg);
	p.fillRect(0, 0, st::notifyBorderWidth, height(), st::notifyBorder);
	p.fillRect(width() - st::notifyBorderWidth, 0, st::notifyBorderWidth, height(), st::notifyBorder);
	p.fillRect(st::notifyBorderWidth, height() - st::notifyBorderWidth, width() - 2 * st::notifyBorderWidth, st::notifyBorderWidth, st::notifyBorder);
}

Notification::Notification(
	not_null<Manager*> manager,
	not_null<History*> history,
	MsgId topicRootId,
	PeerId monoforumPeerId,
	not_null<PeerData*> peer,
	const QString &author,
	HistoryItem *item,
	const Data::ReactionId &reaction,
	int forwardedCount,
	bool fromScheduled,
	QPoint startPosition,
	int shift,
	Direction shiftDirection)
: Widget(manager, startPosition, shift, shiftDirection)
, _peer(peer)
, _started(crl::now())
, _history(history)
, _topic(history->peer->forumTopicFor(topicRootId))
, _topicRootId(topicRootId)
, _sublist(history->peer->monoforumSublistFor(monoforumPeerId))
, _monoforumPeerId(monoforumPeerId)
, _userpicView(_peer->userpicPaintingPeer()->createUserpicView())
, _author(author)
, _reaction(reaction)
, _item(item)
, _forwardedCount(forwardedCount)
, _fromScheduled(fromScheduled)
, _close(this, st::notifyClose)
, _reply(this, tr::lng_notification_reply(), st::defaultBoxButton) {
	_reply->setTextTransform(Ui::RoundButtonTextTransform::ToUpper);

	Lang::Updated(
	) | rpl::on_next([=] {
		refreshLang();
	}, lifetime());

	if (_topic) {
		_topic->destroyed(
		) | rpl::on_next([=] {
			unlinkHistory();
		}, lifetime());
	}

	auto position = computePosition(st::notifyMinHeight);
	updateGeometry(position.x(), position.y(), st::notifyWidth, st::notifyMinHeight);

	_userpicLoaded = !Ui::PeerUserpicLoading(_userpicView);
	updateNotifyDisplay();

	_hideTimer.setSingleShot(true);
	connect(&_hideTimer, &QTimer::timeout, [=] { startHiding(); });

	_close->setClickedCallback([this] {
		unlinkHistoryInManager();
	});
	_close->setAcceptBoth(true);
	_close->moveToRight(st::notifyClosePos.x(), st::notifyClosePos.y());
	_close->show();

	_reply->setClickedCallback([this] {
		showReplyField();
	});
	_replyPadding = st::notifyMinHeight - st::notifyPhotoPos.y() - st::notifyPhotoSize;
	updateReplyGeometry();
	_reply->hide();

	prepareActionsCache();

	style::PaletteChanged(
	) | rpl::on_next([=] {
		updateNotifyDisplay();
		if (!_buttonsCache.isNull()) {
			prepareActionsCache();
		}
		update();
		if (_background) {
			_background->update();
		}
	}, lifetime());

	show();
#if defined QT_FEATURE_wayland && QT_CONFIG(wayland)
	if (_layerSurface) {
		ensureLayerSurface();
		submitLayerFrame();
	}
#endif
}

void Notification::updateReplyGeometry() {
	_reply->moveToRight(_replyPadding, height() - _reply->height() - _replyPadding);
}

void Notification::refreshLang() {
	InvokeQueued(this, [this] { updateReplyGeometry(); });
}

void Notification::prepareActionsCache() {
	auto replyCache = Ui::GrabWidget(_reply);
	auto fadeWidth = st::notifyFadeRight.width();
	auto actionsTop = st::notifyTextTop + st::semiboldFont->height;
	auto replyRight = _replyPadding - st::notifyBorderWidth;
	auto actionsCacheWidth = _reply->width() + replyRight + fadeWidth;
	auto actionsCacheHeight = height() - actionsTop - st::notifyBorderWidth;
	auto actionsCacheImg = QImage(
		QSize(actionsCacheWidth, actionsCacheHeight)
			* style::DevicePixelRatio(),
		QImage::Format_ARGB32_Premultiplied);
	actionsCacheImg.setDevicePixelRatio(style::DevicePixelRatio());
	actionsCacheImg.fill(Qt::transparent);
	{
		Painter p(&actionsCacheImg);
		st::notifyFadeRight.fill(p, style::rtlrect(0, 0, fadeWidth, actionsCacheHeight, actionsCacheWidth));
		p.fillRect(style::rtlrect(fadeWidth, 0, actionsCacheWidth - fadeWidth, actionsCacheHeight, actionsCacheWidth), st::notificationBg);
		p.drawPixmapRight(replyRight, _reply->y() - actionsTop, actionsCacheWidth, replyCache);
	}
	_buttonsCache = Ui::PixmapFromImage(std::move(actionsCacheImg));
}

bool Notification::checkLastInput(
		bool hasReplyingNotifications,
		std::optional<crl::time> lastInputTime) {
	if (!_waitingForInput) return true;

	using namespace Platform::Notifications;
	const auto waitForUserInput = WaitForInputForCustom()
		&& lastInputTime.has_value()
		&& (*lastInputTime <= _started);

	if (!waitForUserInput) {
		_waitingForInput = false;
		if (!hasReplyingNotifications) {
			_hideTimer.start(st::notifyWaitLongHide);
		}
		return true;
	}
	return false;
}

void Notification::replyResized() {
	changeHeight(st::notifyMinHeight + _replyArea->height() + st::notifyBorderWidth);
}

void Notification::replyCancel() {
	unlinkHistoryInManager();
}

void Notification::updateGeometry(int x, int y, int width, int height) {
	if (height > st::notifyMinHeight) {
		if (!_background) {
			_background.create(this);
		}
		_background->setGeometry(0, st::notifyMinHeight, width, height - st::notifyMinHeight);
	} else if (_background) {
		_background.destroy();
	}
	Widget::updateGeometry(x, y, width, height);
}

void Notification::paintEvent(QPaintEvent *e) {
	repaintText();

	Painter p(this);
	p.setClipRect(e->rect());
	p.drawImage(0, 0, _cache);

	auto buttonsTop = st::notifyTextTop + st::semiboldFont->height;
	if (a_actionsOpacity.animating()) {
		p.setOpacity(a_actionsOpacity.value(1.));
		p.drawPixmapRight(st::notifyBorderWidth, buttonsTop, width(), _buttonsCache);
	} else if (_actionsVisible) {
		p.drawPixmapRight(st::notifyBorderWidth, buttonsTop, width(), _buttonsCache);
	}
}

void Notification::actionsOpacityCallback() {
	update();
#if defined QT_FEATURE_wayland && QT_CONFIG(wayland)
	if (layerSurfaceActive()) {
		submitLayerFrame();
	}
#endif
	if (!a_actionsOpacity.animating() && _actionsVisible) {
		_reply->show();
	}
}

void Notification::customEmojiCallback() {
	if (_textsRepaintScheduled) {
		return;
	}
	_textsRepaintScheduled = true;
	crl::on_main(this, [=] { repaintText(); });
}

void Notification::repaintText() {
	if (!_textsRepaintScheduled) {
		return;
	}
	_textsRepaintScheduled = false;
	if (_cache.isNull()) {
		return;
	}
	Painter p(&_cache);
	const auto adjusted = Ui::Text::AdjustCustomEmojiSize(st::emojiSize);
	const auto skip = (adjusted - st::emojiSize + 1) / 2;
	const auto margin = QMargins{ skip, skip, skip, skip };
	p.fillRect(_titleRect.marginsAdded(margin), st::notificationBg);
	p.fillRect(_textRect.marginsAdded(margin), st::notificationBg);
	paintTitle(p);
	paintText(p);
	update();
}

void Notification::paintTitle(Painter &p) {
	p.setPen(st::dialogsNameFg);
	p.setFont(st::semiboldFont);
	_titleCache.draw(p, {
		.position = _titleRect.topLeft(),
		.availableWidth = _titleRect.width(),
		.palette = &st::dialogsTextPalette,
		.spoiler = Ui::Text::DefaultSpoilerCache(),
		.pausedEmoji = On(PowerSaving::kEmojiChat),
		.pausedSpoiler = On(PowerSaving::kChatSpoiler),
		.elisionLines = 1,
	});
}

void Notification::paintText(Painter &p) {
	p.setPen(st::dialogsTextFg);
	p.setFont(st::dialogsTextFont);
	_textCache.draw(p, {
		.position = _textRect.topLeft(),
		.availableWidth = _textRect.width(),
		.palette = &st::dialogsTextPalette,
		.spoiler = Ui::Text::DefaultSpoilerCache(),
		.pausedEmoji = On(PowerSaving::kEmojiChat),
		.pausedSpoiler = On(PowerSaving::kChatSpoiler),
		.elisionHeight = _textRect.height(),
	});
}

void Notification::updateNotifyDisplay() {
	if (!_history || (!_item && _forwardedCount < 2)) {
		return;
	}

	const auto options = manager()->getNotificationOptions(
		_item,
		(_reaction.empty()
			? Data::ItemNotificationType::Message
			: Data::ItemNotificationType::Reaction));
	_hideReplyButton = options.hideReplyButton;

	int32 w = width(), h = height();
	auto img = QImage(
		size() * style::DevicePixelRatio(),
		QImage::Format_ARGB32_Premultiplied);
	img.setDevicePixelRatio(style::DevicePixelRatio());
	img.fill(st::notificationBg->c);

	{
		Painter p(&img);
		p.fillRect(0, 0, w - st::notifyBorderWidth, st::notifyBorderWidth, st::notifyBorder);
		p.fillRect(w - st::notifyBorderWidth, 0, st::notifyBorderWidth, h - st::notifyBorderWidth, st::notifyBorder);
		p.fillRect(st::notifyBorderWidth, h - st::notifyBorderWidth, w - st::notifyBorderWidth, st::notifyBorderWidth, st::notifyBorder);
		p.fillRect(0, st::notifyBorderWidth, st::notifyBorderWidth, h - st::notifyBorderWidth, st::notifyBorder);

		if (!options.hideNameAndPhoto) {
			if (_fromScheduled && _history->peer->isSelf()) {
				Ui::EmptyUserpic::PaintSavedMessages(p, st::notifyPhotoPos.x(), st::notifyPhotoPos.y(), width(), st::notifyPhotoSize);
				_userpicLoaded = true;
			} else if (_history->peer->isRepliesChat()) {
				Ui::EmptyUserpic::PaintRepliesMessages(p, st::notifyPhotoPos.x(), st::notifyPhotoPos.y(), width(), st::notifyPhotoSize);
				_userpicLoaded = true;
			} else {
				_userpicView = _history->peer->createUserpicView();
				_history->peer->loadUserpic();
				_history->peer->paintUserpicLeft(p, _userpicView, st::notifyPhotoPos.x(), st::notifyPhotoPos.y(), width(), st::notifyPhotoSize);
			}
		} else {
			p.drawPixmap(st::notifyPhotoPos.x(), st::notifyPhotoPos.y(), manager()->hiddenUserpicPlaceholder());
			_userpicLoaded = true;
		}

		int32 itemWidth = w - st::notifyPhotoPos.x() - st::notifyPhotoSize - st::notifyTextLeft - st::notifyClosePos.x() - st::notifyClose.width;

		QRect rectForName(st::notifyPhotoPos.x() + st::notifyPhotoSize + st::notifyTextLeft, st::notifyTextTop, itemWidth, st::semiboldFont->height);
		const auto reminder = _fromScheduled && _history->peer->isSelf();
		if (!options.hideNameAndPhoto) {
			if (_fromScheduled) {
				static const auto emoji = Ui::Emoji::Find(QString::fromUtf8("\xF0\x9F\x93\x85"));
				const auto size = Ui::Emoji::GetSizeNormal()
					/ style::DevicePixelRatio();
				const auto top = rectForName.top() + (st::semiboldFont->height - size) / 2;
				Ui::Emoji::Draw(p, emoji, Ui::Emoji::GetSizeNormal(), rectForName.left(), top);
				rectForName.setLeft(rectForName.left() + size + st::semiboldFont->spacew);
			}
			const auto chatTypeIcon = _topic
				? nullptr
				: Dialogs::Ui::ChatTypeIcon(_history->peer);
			if (chatTypeIcon) {
				chatTypeIcon->paint(p, rectForName.topLeft(), w);
				rectForName.setLeft(rectForName.left()
					+ chatTypeIcon->width()
					+ st::dialogsChatTypeSkip);
			}
		}

		const auto composeText = !options.hideMessageText
			|| (!_reaction.empty() && !options.hideNameAndPhoto);
		if (composeText) {
			auto old = base::take(_textCache);
			_textCache = Ui::Text::String(itemWidth);
			auto r = QRect(
				st::notifyPhotoPos.x() + st::notifyPhotoSize + st::notifyTextLeft,
				st::notifyItemTop + st::semiboldFont->height,
				itemWidth,
				2 * st::dialogsTextFont->height);
			const auto text = !_reaction.empty()
				? (!_author.isEmpty()
					? Ui::Text::Colorized(_author).append(' ')
					: TextWithEntities()
				).append(Manager::ComposeReactionNotification(
					_item,
					_reaction,
					options.hideMessageText))
				: _item
				? _item->toPreview({
					.hideSender = reminder,
					.generateImages = false,
					.spoilerLoginCode = options.spoilerLoginCode,
				}).text
				: ((!_author.isEmpty()
						? Ui::Text::Colorized(_author)
						: TextWithEntities()
					).append(_forwardedCount > 1
						? ('\n' + tr::lng_forward_messages(
							tr::now,
							lt_count,
							_forwardedCount))
						: QString()));
			const auto options = TextParseOptions{
				(TextParseColorized
					| TextParseMarkdown
					| (_forwardedCount > 1 ? TextParseMultiline : 0)),
				0,
				0,
				Qt::LayoutDirectionAuto,
			};
			const auto context = Core::TextContext({
				.session = &_history->session(),
				.repaint = [=] { customEmojiCallback(); },
			});
			_textCache.setMarkedText(
				st::dialogsTextStyle,
				text,
				options,
				context);
			_textRect = r;
			paintText(p);
			if (!_textCache.hasPersistentAnimation() && !_topic) {
				_textCache = Ui::Text::String();
			}
		} else {
			p.setFont(st::dialogsTextFont);
			p.setPen(st::dialogsTextFgService);
			p.drawText(
				st::notifyPhotoPos.x() + st::notifyPhotoSize + st::notifyTextLeft,
				st::notifyItemTop + st::semiboldFont->height + st::dialogsTextFont->ascent,
				st::dialogsTextFont->elided(
					tr::lng_notification_preview(tr::now),
					itemWidth));
		}

		const auto topicWithChat = [&]() -> TextWithEntities {
			const auto name = st::wrap_rtl(_history->peer->name());
			return _topic
				? _topic->titleWithIcon().append(u" ("_q + name + ')')
				: TextWithEntities{ name };
		};
		auto title = options.hideNameAndPhoto
			? TextWithEntities{ u"Telegram Desktop"_q }
			: reminder
			? tr::lng_notification_reminder(tr::now, tr::marked)
			: topicWithChat();
		const auto fullTitle = manager()->addTargetAccountName(
			std::move(title),
			&_history->session());
		const auto context = Core::TextContext({
			.session = &_history->session(),
			.repaint = [=] { customEmojiCallback(); },
		});
		_titleCache.setMarkedText(
			st::semiboldTextStyle,
			fullTitle,
			Ui::NameTextOptions(),
			context);
		_titleRect = rectForName;
		paintTitle(p);
	}

	_cache = std::move(img);
	if (!canReply()) {
		toggleActionButtons(false);
	}
	update();
}

void Notification::updatePeerPhoto() {
	if (_userpicLoaded) {
		return;
	}
	_userpicView = _peer->createUserpicView();
	if (Ui::PeerUserpicLoading(_userpicView)) {
		return;
	}
	_userpicLoaded = true;

	Painter p(&_cache);
	p.fillRect(
		style::rtlrect(
			QRect(
				st::notifyPhotoPos,
				QSize(st::notifyPhotoSize, st::notifyPhotoSize)),
			width()),
		st::notificationBg);
	_peer->paintUserpicLeft(
		p,
		_userpicView,
		st::notifyPhotoPos.x(),
		st::notifyPhotoPos.y(),
		width(),
		st::notifyPhotoSize);
	_userpicView = {};
	update();
#if defined QT_FEATURE_wayland && QT_CONFIG(wayland)
	if (layerSurfaceActive()) {
		submitLayerFrame();
	}
#endif
}

bool Notification::unlinkItem(HistoryItem *deleted) {
	auto unlink = (_item && _item == deleted);
	if (unlink) {
		_item = nullptr;
		unlinkHistory();
	}
	return unlink;
}

bool Notification::canReply() const {
	return !_hideReplyButton
		&& (_item != nullptr)
		&& !Core::App().passcodeLocked()
		&& (Core::App().settings().notifyView()
			<= Core::Settings::NotifyView::ShowPreview);
}

void Notification::unlinkHistoryInManager() {
	manager()->unlinkFromShown(this);
}

void Notification::toggleActionButtons(bool visible) {
	if (_actionsVisible != visible) {
		_actionsVisible = visible;
		a_actionsOpacity.start([this] { actionsOpacityCallback(); }, _actionsVisible ? 0. : 1., _actionsVisible ? 1. : 0., st::notifyActionsDuration);
		_reply->clearState();
		_reply->hide();
	}
}

void Notification::showReplyField() {
	if (!_item) {
		return;
	}
#if defined QT_FEATURE_wayland && QT_CONFIG(wayland)
	if (!layerSurfaceActive()) {
		raise();
		activateWindow();
	}
#else
	raise();
	activateWindow();
#endif

	if (_replyArea) {
		_replyArea->setFocus();
		return;
	}
	stopHiding();

	_background.create(this);
	_background->setGeometry(0, st::notifyMinHeight, width(), st::notifySendReply.height + st::notifyBorderWidth);
	_background->show();

	_replyArea.create(
		this,
		st::notifyReplyArea,
		Ui::InputField::Mode::MultiLine,
		tr::lng_message_ph());
	_replyArea->resize(width() - st::notifySendReply.width - 2 * st::notifyBorderWidth, st::notifySendReply.height);
	_replyArea->moveToLeft(st::notifyBorderWidth, st::notifyMinHeight);
	_replyArea->show();
	_replyArea->setFocus();
	_replyArea->setMaxLength(
		Data::PremiumLimits(&_item->history()->session()).messageLengthCurrent());
	_replyArea->setSubmitSettings(Ui::InputField::SubmitSettings::Both);
	InitMessageFieldHandlers({
		.session = &_item->history()->session(),
		.field = _replyArea.data(),
	});

	// Catch mouse press event to activate the window.
	QCoreApplication::instance()->installEventFilter(this);
	_replyArea->heightChanges(
	) | rpl::on_next([=] {
		replyResized();
	}, _replyArea->lifetime());
	_replyArea->submits(
	) | rpl::on_next([=] { sendReply(); }, _replyArea->lifetime());
	_replyArea->cancelled(
	) | rpl::on_next([=] {
		replyCancel();
	}, _replyArea->lifetime());

	_replySend.create(this, st::notifySendReply);
	_replySend->moveToRight(st::notifyBorderWidth, st::notifyMinHeight);
	_replySend->show();
	_replySend->setClickedCallback([this] { sendReply(); });

	toggleActionButtons(false);

	replyResized();
	update();
}

void Notification::sendReply() {
	if (!_history) return;

	manager()->notificationReplied(
		myId(),
		_replyArea->getTextWithAppliedMarkdown());

	manager()->startAllHiding();
}

Notifications::Manager::NotificationId Notification::myId() const {
	if (!_history) {
		return {};
	}
	return { .contextId = {
		.sessionId = _history->session().uniqueId(),
		.peerId = _history->peer->id,
		.topicRootId = _topicRootId,
	}, .msgId = _item ? _item->id : ShowAtUnreadMsgId };
}

void Notification::changeHeight(int newHeight) {
	manager()->changeNotificationHeight(this, newHeight);
}

bool Notification::unlinkHistory(
		History *history,
		MsgId topicRootId,
		PeerId monoforumPeerId) {
	const auto unlink = _history
		&& (history == _history || !history)
		&& (topicRootId == _topicRootId || !topicRootId)
		&& (monoforumPeerId == _monoforumPeerId || !monoforumPeerId);
	if (unlink) {
		hideFast();
		_history = nullptr;
		_topic = nullptr;
		_item = nullptr;
	}
	return unlink;
}

bool Notification::unlinkSession(not_null<Main::Session*> session) {
	const auto unlink = _history && (&_history->session() == session);
	if (unlink) {
		hideFast();
		_history = nullptr;
		_item = nullptr;
	}
	return unlink;
}

void Notification::enterEventHook(QEnterEvent *e) {
	if (!_history) {
		return;
	}
	manager()->stopAllHiding();
	if (!_replyArea && canReply()) {
		toggleActionButtons(true);
	}
}

void Notification::leaveEventHook(QEvent *e) {
	if (!_history) {
		return;
	}
	manager()->startAllHiding();
	toggleActionButtons(false);
}

void Notification::startHiding() {
	if (!_history) return;
	hideSlow();
}

void Notification::mousePressEvent(QMouseEvent *e) {
	if (!_history) return;

	if (e->button() == Qt::RightButton) {
		unlinkHistoryInManager();
	} else {
		e->ignore();
		manager()->notificationActivated(myId(), {
			.allowNewWindow = true,
		});
	}
}

bool Notification::eventFilter(QObject *o, QEvent *e) {
	if (e->type() == QEvent::MouseButtonPress) {
		if (auto receiver = qobject_cast<QWidget*>(o)) {
			if (isAncestorOf(receiver)) {
#if defined QT_FEATURE_wayland && QT_CONFIG(wayland)
				if (layerSurfaceActive()) {
					return false;
				}
#endif
				raise();
				activateWindow();
			}
		}
	}
	return false;
}

void Notification::stopHiding() {
	if (!_history) return;
	_hideTimer.stop();
	Widget::hideStop();
}

HideAllButton::HideAllButton(
	not_null<Manager*> manager,
	QPoint startPosition,
	int shift,
	Direction shiftDirection)
: Widget(manager, startPosition, shift, shiftDirection) {
	setCursor(style::cur_pointer);

	auto position = computePosition(st::notifyHideAllHeight);
	updateGeometry(position.x(), position.y(), st::notifyWidth, st::notifyHideAllHeight);

	style::PaletteChanged(
	) | rpl::on_next([=] {
		update();
	}, lifetime());

	show();
#if defined QT_FEATURE_wayland && QT_CONFIG(wayland)
	if (_layerSurface) {
		ensureLayerSurface();
		submitLayerFrame();
	}
#endif
}

void HideAllButton::startHiding() {
	hideSlow();
}

void HideAllButton::startHidingFast() {
	hideFast();
}

void HideAllButton::stopHiding() {
	hideStop();
}

void HideAllButton::enterEventHook(QEnterEvent *e) {
	_mouseOver = true;
	update();
}

void HideAllButton::leaveEventHook(QEvent *e) {
	_mouseOver = false;
	update();
}

void HideAllButton::mousePressEvent(QMouseEvent *e) {
	_mouseDown = true;
}

void HideAllButton::mouseReleaseEvent(QMouseEvent *e) {
	auto mouseDown = base::take(_mouseDown);
	if (mouseDown && _mouseOver) {
		manager()->clearAll();
	}
}

void HideAllButton::paintEvent(QPaintEvent *e) {
	Painter p(this);
	p.setClipRect(e->rect());

	p.fillRect(rect(), _mouseOver ? st::lightButtonBgOver : st::lightButtonBg);
	p.fillRect(0, 0, width(), st::notifyBorderWidth, st::notifyBorder);
	p.fillRect(0, height() - st::notifyBorderWidth, width(), st::notifyBorderWidth, st::notifyBorder);
	p.fillRect(0, st::notifyBorderWidth, st::notifyBorderWidth, height() - 2 * st::notifyBorderWidth, st::notifyBorder);
	p.fillRect(width() - st::notifyBorderWidth, st::notifyBorderWidth, st::notifyBorderWidth, height() - 2 * st::notifyBorderWidth, st::notifyBorder);

	p.setFont(st::defaultLinkButton.font);
	p.setPen(_mouseOver ? st::lightButtonFgOver : st::lightButtonFg);
	p.drawText(rect(), tr::lng_notification_hide_all(tr::now), style::al_center);
}

} // namespace internal
} // namespace Default
} // namespace Notifications
} // namespace Window
