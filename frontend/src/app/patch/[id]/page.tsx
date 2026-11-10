import PatchView from "@/components/views/PatchView";

export function generateStaticParams() {
  return [{ id: "demo" }, { id: "latest" }, { id: "sample" }];
}

export default function Page() {
  return <PatchView />;
}
